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

/** The sign-in gate answered (dashboard.md §6.z): the session ended (signed
 *  out elsewhere, 12 hours unused, the account changed, the dashboard
 *  restarted). The page reloads once, and the reload is the sign-in page,
 *  which brings the person back here after. */
let signInReloading = false;
function signInEnded(status, data) {
  if (status !== 401 || !data || typeof data.error !== 'string' || !/^sign in required/.test(data.error)) return false;
  if (!signInReloading) {
    signInReloading = true;
    try { window.location.reload(); } catch { /* no window to reload */ }
  }
  return true;
}

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
    signInEnded(res.status, data);
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
  signInEnded(res.status, data);
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
// A dashboard that did not start its protection service (it was already
// running, so the dashboard adopted it) holds no admin channel, and every
// answer and change is refused before anything runs: "admin channel
// unavailable: …" from the adapter (server/http-util.ts), bare, in the
// brackets of the label route, after "arbiter: " or "<op> failed: ", or
// "admin-only: …" from the service itself for one that reached its data
// socket.
const ADMIN_CHANNEL_REFUSAL = /(?:^|[\s(])(?:admin channel unavailable|admin-only):/;
// The page's own sentences that name a command or a place (dashboard.md
// §4.25 "Refusals"): a part given as ['…'] is the command, one given as
// { to, text } a link placeLink draws. Each is a plain string (no quotes, no
// backticks) wherever only a string fits; `words()` draws it with the
// command as code, as every command the page names is, and the place as
// its link. A command the sentence asks you to run is marked so,
// ['mandu stop', 'run'], and drawn with its Copy (runCode, §4.25b): the
// mark is not in the text, so the sentence is the same string either way.
const OWN_WORDS = new Map();
function ownWords(...parts) {
  const text = parts.map((p) => (Array.isArray(p) ? p[0] : typeof p === 'object' ? p.text : p)).join('');
  OWN_WORDS.set(text, parts);
  return text;
}
const SIGN_IN_WORDS = ownWords('Sign in first: reload this page and sign in with your dashboard account (if there isn\'t one yet, run ', ['mandu dashboard --set-password', 'run'], ' in your own terminal).');
const NOT_CONNECTED_WORDS = 'The protection service is not connected.';
// Settings has the Start of the service, at its top: the words link there,
// as in the hero and on the agent page.
const UNREACHABLE_WORDS = ownWords('The protection service is not running. ', { to: 'settings', text: 'Start it under Settings' }, ', or try again in a moment.');
// The two failures of the dashboard itself, in the words of the hero
// (§4.25, *The hero says why in words*): no answer at all, or an error.
const NO_ANSWER_WORDS = 'The dashboard could not reach its own server. Refresh in a moment.';
// The way out (dashboard.md §4.25 *An answer this dashboard cannot pass
// on*): `mandu stop` stops the dashboard and the service, and the next
// start (the launch of an agent, or the systemd service bringing the dashboard
// back) gives a dashboard that starts the service itself.
const ADMIN_CHANNEL_WORDS = ownWords('This dashboard cannot pass on your answers: the protection service was already running when the dashboard started. Nothing was changed. To fix it, run ', ['mandu stop', 'run'], ' when no agent is running with mandu, then start your agent again.');
function errorWords(status) { return 'The dashboard server answered with an error (' + status + '). Refresh in a moment.'; }
/** Where a signed-out page would show a real value (dashboard.md §6). */
const SIGN_IN_VALUES = 'Sign in to see real values: reload this page and sign in with your dashboard account.';

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
  if (ADMIN_CHANNEL_REFUSAL.test(error)) return ADMIN_CHANNEL_WORDS;
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
function cannotCheck(lead, cause, link, off) {
  // Mandu not running at all (offCause): no fault and no lead, the place
  // (`off`: "your rule changes show here") and how Mandu starts.
  if (cause === 'not-running') return [words(notRunningWords(off))];
  const why = cause === 'down' ? (link ? words(UNREACHABLE_WORDS) : 'The protection service is not running.')
    : cause === 'gone' ? NO_ANSWER_WORDS
    : cause === 'not-connected' ? NOT_CONNECTED_WORDS
    : cause ? errorWords(cause)
    : 'The protection service may be unreachable.';
  return [lead + ' ', why];
}
// ── Before Mandu runs, a line says so (dashboard.md §4.25 *Protection is off
// when nothing runs*) ─────────────────────────────────────────────────────────
/** The latest Home poll says Mandu is not running at all: the server found
 *  no service, no instance starting and no launch alive (mandu-running.ts).
 *  Only that answer selects the words below, never a guess of the page. */
function notRunningNow() {
  return !!(S.home && S.home.protection && S.home.protection.notRunning);
}
/** A could-not cause while Mandu is not running: one that tells only that no
 *  service answered (none known, `down`, `not-connected`) is `not-running`
 *  then. No answer of the dashboard and an error of its own stay faults. */
function offCause(cause) {
  return notRunningNow() && (cause == null || cause === 'down' || cause === 'not-connected') ? 'not-running' : cause;
}
/** The sentence of a place while Mandu is not running, in the words of
 *  Settings › Protection, the commands as code: `what` names the place
 *  ("your rule changes show here"). One of the own words of the page
 *  (ownWords), so a string, which a line keeps to know when to draw again. */
function notRunningWords(what) {
  const codes = startList(S.home).flatMap((c, i) => (i ? [' or ', [c]] : [[c]]));
  return ownWords('Mandu is not running now; ' + what + ' once it starts with your first agent: ', ...codes, '.');
}
/** What a line drawn while Mandu is not running depends on, for its
 *  sameAsDrawn key: the state, the setup card and the commands. Null while
 *  it runs, or no poll answered. */
function offKey() {
  return notRunningNow() ? ['not running', !!S.home.firstRun, startList(S.home)] : null;
}
/** Whether a refused read (`r`, an apiGetControl answer) says only that no
 *  service answered: the 404 of no service behind the route (in its own
 *  words, or in those of the page, as the prompt filter route answers it),
 *  its 503 `unreachable`, or the 502 of a dial that failed. */
function noService(r) {
  if (!r || !r.status) return false;
  const error = r.data && typeof r.data.error === 'string' ? r.data.error : '';
  return (r.status === 404 && (NOT_CONNECTED_REFUSAL.test(error) || error === NOT_CONNECTED_WORDS)) || r.status === 502
    || (r.status === 503 && !!r.data && r.data.unreachable === true) || UNREACHABLE_REFUSAL.test(error);
}
/** Why the policy panel could not be read: the failure of its own read, else,
 *  when it answered `available: false` (no service behind the route, which
 *  a dashboard with none configured answers too), the cause of the latest
 *  Home poll if that one is not an error of the dashboard: the service not
 *  running, or no answer at all. Mandu not running at all: `not-running`
 *  (offCause). */
function panelCause(failure) {
  if (failure) return offCause(failure);
  return offCause(S.homeFailure === 'down' || S.homeFailure === 'gone' ? S.homeFailure : null);
}
/** Rules › Your rules and Settings › Models take that cause when drawn, and
 *  a Home poll that ended after their read, or knows another cause now,
 *  draws their line again: only a changed cause, so a focused "add a rule"
 *  stays as it is. Settings › Prompt filters follows the same way. */
function followCannotCheck() {
  followFilesNote();
  if (S.page === 'rules' && !S.panel && F.unreadCause !== false && F.unreadCause !== causeKey(panelCause(S.panelFailure))) renderLabeled();
  if (S.page === 'settings' && M.unread && M.unread.shown !== causeKey(panelCause(M.unread.failure))) drawModelsUnread(document.getElementById('settings-models'));
  if (S.page === 'settings' && S.promptUnread && S.promptUnread.shown !== promptUnreadWords(S.promptUnread)) drawPromptUnread();
  if (S.page === 'settings' && S.labelsUnread && S.labelsUnread.shown !== labelsUnreadWords(S.labelsUnread.r)) drawLabelsUnread();
}
/** A cause as a line drawn with it keeps it: `not-running` with the
 *  commands its sentence names, which a scan meanwhile can change. */
function causeKey(cause) {
  return cause === 'not-running' ? cause + ':' + startList(S.home).join(',') : cause;
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
 *  command as code (with its Copy when marked 'run') and its place as a link; any other text, such as a
 *  server's error, as written, one text node. */
function words(text) {
  const parts = OWN_WORDS.get(text);
  if (!parts) return document.createTextNode(text == null ? '' : String(text));
  const frag = document.createDocumentFragment();
  for (const p of parts) frag.append(Array.isArray(p) ? (p[1] === 'run' ? runCode(p[0]) : ownCode(p[0])) : typeof p === 'object' ? placeLink(p) : p);
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
/** The commands a sentence starts your agent with: the agents you use,
 *  as the `start` of `/api/home` names them (at most two; dashboard.md §4.25,
 *  *Protection is off when nothing runs*), or the two of old when Mandu knows
 *  none or an older server sends none. */
const START_FALLBACK = ['mandu claude', 'mandu codex'];
/** The `start` of the Home answer as sent (at most two), or null with no
 *  answer or an older server that sends none. */
function homeStart(home) {
  const s = home && Array.isArray(home.start) ? home.start.filter((c) => typeof c === 'string' && c !== '').slice(0, 2) : [];
  return s.length ? s : null;
}
function startList(home) {
  return homeStart(home) || START_FALLBACK;
}
/** The commands in plain words, `a` or `a (or b)`. */
function startWords(home) {
  const s = startList(home);
  return s.length > 1 ? s[0] + ' (or ' + s[1] + ')' : s[0];
}
/** Server parts with each run of `start` parts (the commands of the Scan
 *  page, built from its kept scan alone) named from `list` in the form of
 *  that page, `a` or `a` (or `b`) (dashboard.md §4.25ai); no list: as sent. */
function withStart(parts, list) {
  if (!list || !Array.isArray(parts)) return parts;
  const out = [];
  parts.forEach((p, i) => {
    if (!p || p.start !== true) { out.push(p); return; }
    if (i > 0 && parts[i - 1] && parts[i - 1].start === true) return;
    out.push({ kind: 'code', text: list[0] });
    if (list.length > 1) out.push({ kind: 'text', text: ' (or ' }, { kind: 'code', text: list[1] }, { kind: 'text', text: ')' });
  });
  return out;
}
/** The commands as code, `a` or `a` or `b`, for a sentence to hold. */
function startCodes(home) {
  const s = startList(home);
  return s.length > 1 ? [ownCode(s[0]), ' or ', ownCode(s[1])] : [ownCode(s[0])];
}
/** The same with a Copy beside each (runCode), for Settings › Protection
 *  while Mandu is not running (dashboard.md §4.25 *Protection is off when
 *  nothing runs*, *Said once*). */
function startRunCodes(home) {
  return startList(home).flatMap((c, i) => (i ? [' or ', runCode(c)] : [runCode(c)]));
}
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
 *  nameCode, the words around them through countWords, a link part as
 *  placeLink draws it (the Rules of `ifStandingParts`). Without parts (an
 *  older server), its plain `text`, as written. */
function askCellWords(parts, text) {
  if (!Array.isArray(parts) || !parts.length) return document.createTextNode(text == null ? '' : String(text));
  const frag = document.createDocumentFragment();
  for (const p of parts) frag.append(p.kind === 'link' ? placeLink(p) : partNode(p, nameCode, countWords));
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
  for (const p of parts) frag.append(p.kind === 'link' ? placeLink(p) : p.kind === 'code' && p.run === true ? runCode(p.text) : partNode(p, ownCode, countWords));
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
 *  its `session`: the agent a Home notice names, §4.25x); or Settings at
 *  its Models card (`models`, the focus on Add a model) or at its Protection
 *  card (`protection`, the focus on the switch); or the rule of one file on
 *  Rules (`rule`, its `path`: the row opened, else Your rules). The page
 *  builds the link; a place it does not know is plain text. */
function placeLink(p) {
  if (p.to === 'settings' || p.to === 'history') return el('a', { href: routeHref(p.to), 'data-page-link': p.to, text: p.text });
  if (p.to === 'agent' && typeof p.session === 'string' && p.session !== '') {
    // A session the hero names (§4.25 *Protection failed in several
    // sessions*): its `parts`, the folder a name that breaks at its slashes,
    // the moment in the clock of this browser.
    const words = Array.isArray(p.parts) && p.parts.length ? p.parts.map((q) => partNode(q, nameCode, (t) => document.createTextNode(t))) : [];
    return el('a', { href: routeHref('agent', p.session), 'data-page-link': 'agent', 'data-session': p.session, ...(words.length ? {} : { text: p.text }) }, ...words);
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
  if (p.to === 'your-rules') {
    // Your rules on this page (Which files, §4.25z), as its section link
    // goes; a modifier click opens Rules at that card.
    return el('a', { href: routeHref('rules') + '#your-rules', 'data-section': 'your-rules', text: p.text, onclick: (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button > 0) return;
      e.preventDefault();
      goToSection('rules', 'your-rules', 'rules-block');
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
  if (p.to === 'models' || p.to === 'protection') {
    // Inside a row that opens on a click (a rule of the tree), the link
    // only opens its card.
    return el('a', { href: routeHref('settings') + '#' + p.to, text: p.text, onclick: (e) => {
      e.stopPropagation();
      if (e.metaKey || e.ctrlKey || e.shiftKey) return;
      e.preventDefault();
      if (p.to === 'models') openModels();
      else openProtection();
    } });
  }
  if (p.to === 'rule' && typeof p.path === 'string' && p.path !== '') {
    // The address names the file only (its rule, opened in a new tab, as
    // Change it in Rules on a session page does): never a value.
    return el('a', { href: routeHref('rules', p.path), text: p.text, 'aria-label': p.text + ': ' + shortPath(p.path), onclick: (e) => {
      e.stopPropagation();
      if (e.metaKey || e.ctrlKey || e.shiftKey) return;
      e.preventDefault();
      openRuleAt(p.path);
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
 *  never part of /api/home. Null until loaded or when it cannot be. Each read
 *  also keeps the deadline of each hold (keepHoldEnds). */
async function loadPromptHolds() {
  try {
    const res = await fetch(BASE + '/api/prompt-filters/holds', { headers: { ...FRONT, 'X-Mandu-Control': '1' } });
    if (!res.ok) return null;
    const d = await res.json();
    const m = new Map();
    for (const h of (d && d.holds) || []) m.set(h.approvalId, h);
    keepHoldEnds(m, d && d.timeoutMs);
    return m;
  } catch {
    return null;
  }
}

/** The deadline of each held message, by the id of its ask (dashboard.md
 *  §4.34, the deadline of a held message): `endsAt` on the clock of this
 *  page, from the time left the route sent when the read arrived, so the
 *  clock of the server never matters; `total` the whole deadline the route
 *  sent. A later read keeps the
 *  earlier end, so a redraw never restarts the count, unless it says the
 *  time is up sooner. */
const HOLD_ENDS = new Map();
const HOLD_TICK_MS = 1000;
let holdTimer = null;
function keepHoldEnds(holds, total) {
  const now = Date.now();
  for (const id of [...HOLD_ENDS.keys()]) if (!holds.has(id)) HOLD_ENDS.delete(id);
  for (const [id, h] of holds) {
    const left = Number(h.timeoutMs);
    if (!Number.isFinite(left)) continue;
    const kept = HOLD_ENDS.get(id);
    const endsAt = now + Math.max(0, left);
    HOLD_ENDS.set(id, {
      endsAt: kept ? Math.min(kept.endsAt, endsAt) : endsAt,
      total: Number(total), firstSeen: Number(h.firstSeen), redact: h.fallback === 'redact',
    });
  }
}

function fillPromptFound(host, holds) {
  for (const node of host.querySelectorAll('.ask-found[data-id]')) {
    const id = node.getAttribute('data-id');
    const h = holds.get(id);
    clear(node);
    const drawn = node.nextElementSibling;
    if (drawn && drawn.classList.contains('ask-hold')) drawn.remove();
    if (!h || typeof h.span !== 'string') continue;
    node.append('It found: ', el('code', { text: h.span }));
    const line = holdLine(id);
    if (line) node.after(line);
  }
  armHoldTick();
}

/** The line under the found text of a held message (dashboard.md §4.34,
 *  the deadline of a held message): how long its request still waits, counted down
 *  each second, then that it went with the default. None when the route
 *  sent no deadline. */
function holdLine(id) {
  const e = HOLD_ENDS.get(id);
  if (!e || !(e.total > 0)) return null;
  const line = el('div', { class: 'ask-hold', 'data-id': id });
  sayHold(line, e);
  return line;
}
/** The words of the line now. While it counts only the text node of the count is
 *  written, never the card (§4.25 *The poll keeps your place*); the line is
 *  no live region then, which would be read every second. The turn of a
 *  counting line to the past sets `role="status"` first, so that change alone is
 *  announced. */
function sayHold(line, e) {
  const left = e.endsAt - Date.now();
  const what = e.redact ? 'removed' : 'masked';
  if (left > 0) {
    const words = n(Math.ceil(left / 1000), 'more second', 'more seconds');
    const count = line.querySelector('.ask-hold-left');
    if (count) { count.firstChild.nodeValue = words; return; }
    line.classList.add('live');
    line.append('The request to the AI waits ', el('span', { class: 'ask-hold-left', text: words }), ' for your answer, then goes with that part ' + what + '.');
    return;
  }
  if (line.classList.contains('past')) return;
  // Each line its own: the short card of the same hold on Home is drawn too,
  // hidden while Approvals is shown. A line first drawn past says nothing.
  if (line.classList.contains('live')) line.setAttribute('role', 'status');
  line.classList.remove('live');
  line.classList.add('past');
  clear(line);
  const at = e.firstSeen > 0 ? whenNode(e.firstSeen + e.total) : null;
  line.append('No answer came within ' + holdWords(e.total) + ', so your message went to the AI with that part ' + what,
    at ? ' at ' : null, at, '. Your answer applies the next time the agent sends it.');
}
function holdWords(ms) {
  const s = Math.round(ms / 1000);
  return s >= 120 && s % 60 === 0 ? n(s / 60, 'minute', 'minutes') : n(s, 'second', 'seconds');
}
/** The one timer, armed only while a counting line is drawn. A line whose
 *  hold a later read no longer lists stops counting. */
function armHoldTick() {
  if (holdTimer !== null || !document.querySelector('.ask-hold.live')) return;
  holdTimer = setTimeout(tickHolds, HOLD_TICK_MS);
}
function tickHolds() {
  holdTimer = null;
  for (const line of document.querySelectorAll('.ask-hold.live')) {
    const e = HOLD_ENDS.get(line.getAttribute('data-id'));
    if (e) sayHold(line, e);
    else line.classList.remove('live');
  }
  armHoldTick();
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
/** What each count means (dashboard.md §4.25 *What the counts mean*): one
 *  list for Home's counts (their tooltips and "?" notes), a session page's
 *  tiles (their tooltips and the fold under them) and the folds of
 *  History and Home (their rows' counts and marks, drawRowMeanings), so
 *  the words cannot drift apart. `term` names the count in a fold, `mark`
 *  a row's mark when its words differ, `help` its "?" button; `means(k)` says it of k.
 *  A page adds where to look ("Your secrets, below, …"); the meaning itself
 *  never does. `less` is the server's words for it (view-model home.ts,
 *  Home's line on a running agent), `failed` Home's alarm's. */
const COUNT_MEANINGS = {
  masked: { term: 'Secrets masked before the AI saw them',
    means: () => 'The AI got only the masked version of each, from the first time it could see it.' },
  early: { term: 'Secrets the AI read before they were marked secrets', help: 'What read before it was marked means',
    means: () => 'The AI read the real value as it was, before it was marked a secret.' },
  blocked: { term: 'Actions blocked', help: 'What blocked means',
    means: () => 'Each is a step Mandu stopped: a command, a file or a send.' },
  sent: { term: 'Sends with a real value filled in', help: 'What a send with a real value means',
    means: (k) => (k === 1 ? 'It' : 'Each') + ' went to a destination allowed to receive it.' },
  off: { term: 'Sessions that ran with protection off', mark: 'Protection was off', help: 'What protection off means',
    means: (k) => 'Mandu only watched in ' + (k === 1 ? 'it' : 'them') + ': nothing was masked or blocked.' },
  less: { term: 'Less protection than usual',
    means: () => 'Not all of Mandu\'s protections started for it.' },
  failed: { term: 'Protection failed',
    means: () => 'Something reached the AI unmasked. Open its page to see what.' },
};
/** A count's "?" (never hover-only, as the masked count's): its meaning. */
function countHelp(kind, k) { return helpButton(COUNT_MEANINGS[kind].help, COUNT_MEANINGS[kind].means(k)); }
/** The notice of an agent row (supported-agents.md §3; dashboard.md §4.21
 *  *On the product page*): a warning mark by its name that opens the
 *  sentence, each command in it as code (`parts`; an older server sends the
 *  plain line only), so the row stays one line. */
function agentNoticeMark(notice, parts) {
  return helpButton('Warning about this agent', Array.isArray(parts) && parts.length ? textParts(parts, notice) : notice, { icon: 'alert', cls: 'notice-btn' });
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
      // A moment (ISO): the local clock time, as each turn's time is drawn;
      // with `clock` (the end of a send rule) its day too, as momentNode.
      // With `step` (a Your secrets card), a link to the step that shows it.
      code = null;
      const time = p.clock ? momentNode(p.text) : el('time', { datetime: p.text, text: hhmm(p.text) || p.text });
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
    } else if (p.href && /^https:\/\//.test(p.href)) {
      // A fixed address the server names (the leak check's Report a
      // problem), in a new tab as the page's other such links.
      code = null;
      s.append(el('a', { href: p.href, target: '_blank', rel: 'noopener noreferrer', text: p.text }));
    } else if (p.rules === 'built-in') {
      // The card of Rules that lists the companies whose keys go to their
      // own API without asking (the note of a sent step, §4.25b), opened
      // there as its section link does; a modifier click is the browser.
      code = null;
      s.append(el('a', { href: routeHref('rules') + '#built-in', text: p.text, onclick: (e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button > 0) return;
        e.preventDefault();
        goToSection('rules', 'built-in', 'builtin-block');
      } }));
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
  // A secret's filter keeps its own marks (foldQuiet).
  for (const x of story.querySelectorAll('.step.shown:not(.secret-kept)')) x.classList.remove('shown');
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
  // A fenced block of text only has a Copy button (dashboard.md §4.25b, *A
  // code block has a Copy button*), outside the box so scrolling never
  // carries it away. None for a block holding a chip (its text is not the
  // value), and none without a clipboard (not a secure context).
  if (canCopy()) {
    for (const pre of s.querySelectorAll('pre.code-block')) {
      if (pre.querySelector('.mask-chip')) continue;
      const wrap = el('div', { class: 'code-wrap' });
      pre.replaceWith(wrap);
      wrap.append(pre, ...copyButton(pre));
    }
  }
  return s;
}
function canCopy() {
  return typeof navigator !== 'undefined' && !!navigator.clipboard && typeof navigator.clipboard.writeText === 'function';
}
/** Copy and its polite status: `source`'s text goes to the clipboard (a
 *  node's as drawn, read at the click, or a string as given); the button
 *  reads Copied (or Could not copy) for two seconds, and the focus stays on
 *  it. `name`, when given, is its accessible name ("Copy mandu scan"). */
function copyButton(source, name, cls) {
  const said = el('span', { class: 'code-copy-said', role: 'status' });
  let back = 0;
  const btn = el('button', { type: 'button', class: 'code-copy' + (cls ? ' ' + cls : ''), 'aria-label': name || null, text: 'Copy' });
  const show = (words) => {
    btn.textContent = words;
    said.textContent = words === 'Copy' ? '' : words;
  };
  btn.addEventListener('click', () => {
    clearTimeout(back);
    navigator.clipboard.writeText(typeof source === 'string' ? source : source.textContent).then(() => 'Copied', () => 'Could not copy').then((words) => {
      show(words);
      back = setTimeout(() => show('Copy'), 2000);
    });
  });
  return [btn, said];
}
/** A command Mandu itself asks you to run (dashboard.md §4.25b, *A command
 *  Mandu asks you to run has one too*): ownCode with a small Copy beside
 *  it, named for what it copies (`name`, else the command itself). Only
 *  the page's own commands come here: the update line, the first-run
 *  commands, the set-up steps on Plugins, a server part marked `run`, an
 *  own-words part marked 'run' (`mandu stop`, `mandu doctor`), `mandu
 *  --version`, `mandu paths` (also on the open-places card of Home),
 *  `mandu dashboard`, Where your data lives'
 *  `mandu doctor` (a broken link), and in index.html the
 *  `code[data-run]` (`mandu dashboard --set-password`, `mandu paths`,
 *  `mandu doctor`);
 *  never a host, a file, a key name or a session's data. No clipboard: the
 *  code alone. */
function runCode(text, name) {
  const code = ownCode(text);
  if (!canCopy()) return code;
  return el('span', { class: 'run-code' }, code, ...copyButton(code.textContent, 'Copy ' + (name || code.textContent), 'run-copy'));
}

/** How long ago `ms` was, by the local calendar and coarser with age
 *  (dashboard.md §4.25u, *Every moment reads absolute and relative*): "just
 *  now", "5 minutes ago"; hours earlier today, or under 6 hours ago across
 *  midnight ("2 hours ago"); "yesterday", the previous local day; "3 days
 *  ago" to 6 days; whole weeks to 29 days ("1 week ago"); whole 30-day
 *  months to 364 days ("3 months ago"); then "over a year ago". */
function ago(ms) {
  if (!Number.isFinite(ms)) return '';
  const nowMs = Date.now();
  const d = Math.max(0, nowMs - ms);
  const m = Math.round(d / 60_000);
  if (m < 1) return 'just now';
  if (m < 60) return n(m, 'minute', 'minutes') + ' ago';
  // Calendar days back: local midnights apart, rounded over a daylight
  // saving day of 23 or 25 hours.
  const now = new Date(nowMs);
  const then = new Date(ms);
  const days = Math.round((new Date(now.getFullYear(), now.getMonth(), now.getDate()) - new Date(then.getFullYear(), then.getMonth(), then.getDate())) / 86_400_000);
  if (days < 1 || d < 6 * 3_600_000) return n(Math.round(m / 60), 'hour', 'hours') + ' ago';
  if (days === 1) return 'yesterday';
  if (days < 7) return days + ' days ago';
  if (days < 30) return n(Math.floor(days / 7), 'week', 'weeks') + ' ago';
  if (days < 365) return n(Math.floor(days / 30), 'month', 'months') + ' ago';
  return 'over a year ago';
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
/** A moment as a full date for a hover: "Tuesday, Dec 1, 2026, 09:00", in
 *  the local clock, the year always named. */
function fullClockWords(ms) {
  const d = new Date(ms);
  const pad = (k) => String(k).padStart(2, '0');
  return WEEKDAYS[d.getDay()] + ', ' + MONTHS[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear() + ', ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}
/** A moment a server part names (`{kind: 'time', text: ISO}`, the end of a
 *  send rule; dashboard.md §4.25u, *A rule with an end date says when*):
 *  <time datetime="ISO" title="Tuesday, Dec 1, 2026, 09:00">Dec 1, 09:00</time>,
 *  in the reader clock as clockWords says it (the year when it is not this
 *  year), the full date on hover. Text that is no date stays its text. */
function momentNode(iso) {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return document.createTextNode(iso == null ? '' : String(iso));
  return el('time', { class: 'moment', datetime: String(iso), title: fullClockWords(ms), text: clockWords(ms) });
}
/** How long until `ms`: "ends in 9 days", "ends in 5 hours", "ends in 1
 *  minute", "ends in under a minute". */
function endsIn(ms) {
  const m = Math.round(Math.max(0, ms - Date.now()) / 60_000);
  if (m < 1) return 'ends in under a minute';
  if (m < 60) return 'ends in ' + n(m, 'minute', 'minutes');
  const h = Math.round(m / 60);
  if (h < 24) return 'ends in ' + n(h, 'hour', 'hours');
  return 'ends in ' + n(Math.round(h / 24), 'day', 'days');
}
/** One part of a server sentence: a name as `code` draws it, a moment as
 *  momentNode, any other kind (words, or a kind this page does not know)
 *  as `words` draws its text. */
function partNode(p, code, words) {
  return p.kind === 'code' ? code(p.text) : p.kind === 'time' ? momentNode(p.text) : words(p.text);
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
    // The "last step" button of the session page is named by its words too.
    const go = Number.isFinite(ms) && t.closest('button.agent-last-go');
    if (go) go.setAttribute('aria-label', lastStepName(ms));
    // So is the "last step" link of a running row, on Home or History.
    const home = Number.isFinite(ms) && t.closest('a.agent-last-link');
    if (home) nameLastStepLink(home);
  }
  // History day headings (historyDay), and those of Answered earlier: past
  // midnight Today reads Yesterday, the rows under it left as they are.
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
const S = { home: null, askNotes: new Map(), builtinFiles: null, builtinFilesLoading: false, panel: null, secrets: null, axes: null, services: null, page: 'home', visit: 0, busy: new Set(), proposals: [], proposalPatternsHidden: false, proposalNotice: null,
  // Why the latest Home poll failed (readFailure), null when it answered;
  // why the policy panel of Rules could not be read (null: not known); and
  // why Settings › Protection could not read config.toml (null: not known).
  homeFailure: null, panelFailure: null, axesFailure: null,
  // The rows Home's Running now and Earlier last drew (renderHomeMeanings).
  homeRows: { agents: [], earlier: [] },
  // The Home polls asked so far, and the latest one whose answer the page
  // took (loadHome): an answer to a poll asked before that one is dropped.
  homeAsked: 0, homeTaken: 0,
  // Settings › About Mandu: the `about` an answer last drew (renderAbout),
  // kept through a poll that fails; null before the first.
  about: null,
  // The question ids and rule-change ids the announcement line of the top bar
  // has met in this tab (announceNewAsks), each null until its first read
  // answered, which records what waits without a word.
  announcedAsks: null, announcedProposals: null,
  // The Settings blocks whose last read left them unread ('labels',
  // 'prompt'), read again when the service comes back (readAgainUnread).
  unread: new Set(),
  // Settings › Prompt filters, unread: its line, the answer it says and the
  // words it was drawn with (drawPromptUnread); null when read.
  promptUnread: null,
  // Settings › Sensitivity labels, unread, the same way (drawLabelsUnread).
  labelsUnread: null,
  // How many exceptions in force the card last read (Try a message says
  // what matches one is not marked).
  promptExceptionsInForce: 0,
  // What runs (runningKey) as Settings › Protection and the Rules line last drew it.
  runningShown: { settings: null, rules: null },
  // What runs on the secrets axis (secretsRunning: 'on' / 'off') as
  // Settings › Prompt filters and Rules' "What the rules say" answers last
  // followed it (followRunningAnswers); null before a poll on that page said.
  runningFollowed: { settings: null, rules: null },
  // The saved on/off ('on' / 'off') of Home's poll that last made the page
  // read the setting again (followSaved); null after the page's own read or
  // flip.
  axesFollowed: null,
  // The service line of Settings › Protection: the summary it was drawn from
  // (`services`, as JSON), its state for the row's dot (protectDot) and how
  // many of its own requests are out (followServices).
  serviceState: null,
  serviceOut: 0,
  // The line was drawn without its sentence (serviceQuiet).
  serviceQuiet: false,
  // A flip of the Protection switch is on its way: the switch holds
  // (flipProtection).
  protectOut: false,
  // What you typed in the ALLOW field of each over-broad rule change, by its id.
  proposalTyped: new Map(),
  // The words of the answer to the last button of each card or row the poll
  // draws, by its place and id (keepAnswer).
  answers: new Map(),
  // The line an answer that worked left where its card was, by its place
  // (answerLine; dashboard.md §4.25 *An answer says what it did*).
  answerLines: new Map(),
  // The short cards of Approvals' *From sessions that have ended* whose What
  // each answer does is open, by question id, so a poll that draws the list
  // again keeps them open (askCard; dashboard.md §4.25 *An ended question is
  // short on Approvals*).
  askOpen: new Set(),
  // The session page's Needs your OK as last drawn ({ visit, id, vm }), so
  // a flip of the phone breakpoint draws it again without a poll
  // (phoneFlipped; dashboard.md §4.25 *A waiting question is short on a
  // phone*).
  agentWaitingShown: null,
  // The rule change whose answer left the line of Rule changes your agent
  // asked for: the heading of the block names it while only the line is there.
  proposalAnswered: null,
  // The lists of the past on Approvals, past their newest 20 (dashboard.md
  // §4.25 *Past the newest 20*): the rows of Answered earlier once Show more
  // brought more (null: the newest 20 of Home), the answer `/approvals/<id>` sought past
  // them (seekAnswered), and how many Rule changes draws (loadRuleHistory),
  // with the change `/approvals/<id>` sought past them (`sought`, seekChanges)
  // and how many the last read taken asked for (`limit`). The search of Rule
  // changes (§4.25 *Finding a rule change*): `changesQ`. The day Answered
  // earlier lists from, back (`answeredDay`, "2026-10-20", its `?day=`;
  // §4.25 *Go to a day on Answered earlier*), or ''. The day Rule changes
  // lists from, back (`changesDay`, its `?cday=`; *Go to a day on Rule
  // changes*), or ''.
  answered: null, answeredSought: null, answeredQ: '', answeredDay: '',
  changes: { want: 20, last: null, failure: null, out: 0, read: false, sought: null, limit: 0 }, changesQ: '', changesDay: '',
  // The heading the last page change gave the focus (focusPage), null before
  // any; the card or step that took it from there (focusMarked).
  pageHeading: null, marked: null,
  // The answer pressed with the focus in its card or row, and where the
  // focus goes once it is answered (holdFocus); null when none.
  answerFocus: null,
  // What the agent page asked to see past its caps this visit (agentShow),
  // where the focus goes once a "Show them" is drawn (landAgent), and the
  // visit whose Earlier list shows every session (renderEarlier;
  // dashboard.md §4.25ad), and the visit whose Files the AI read as they
  // were shows every file the server sent (renderReadAsIs, §4.25b).
  agentShow: null, agentLand: null, earlierAll: null, readAsIsAll: null,
  // While the browser prints: the way back of each fold the print opened
  // (printOpen), and whether a read of the agent page waits for its end.
  printOpened: null, printSkipped: false,
  // Back to the page of a session (dashboard.md §4.25 *Back and Forward keep
  // your place*): the place its entry kept, until the first read of the
  // visit is drawn (agentLandPlace), the visit and session it is for, and
  // the scroll just after the Back (`at`: a scroll since is yours, and wins).
  agentPlace: null,
  // The step each count tile of the agent page last went to, this visit
  // (tileAt; dashboard.md §4.25 *A tile takes you to what it counts*).
  agentTileAt: null,
  // Where the agent page goes once its visit is first drawn, the visit and
  // its kind (a Home count's link, `?go=`; landGo), then null.
  agentGo: null,
  // The agent page shows only the turns where Mandu stepped in (its switch,
  // `?only=stepped-in`; dashboard.md §4.25ae *Only where Mandu stepped in*).
  agentOnly: false,
  // The agent page shows only the turns that hold one secret's steps (its
  // card's Show its steps; dashboard.md §4.25b *A card shows its steps*):
  // { visit, id, key, at } of that card (secretKey; `at`, the step its line
  // last went to, goToSecretStep), this visit only, never in the address;
  // null: off.
  agentSecretOnly: null,
  // The Your secrets cards last drawn (the server's), which it reads.
  agentSecretCards: [],
  // History lists only the sessions where Mandu stepped in (its switch, the
  // same `?only=`; §4.25ae *Only the sessions where Mandu stepped in*).
  historyOnly: false,
  // The day History lists from, back ("2026-10-20", its `?day=`; §4.25ae
  // *Go to a day*), or ''.
  historyDay: '' };

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
 *  words of an answer that worked and leaves the card in place (letDone).
 *  `changeId`: the rule change the answer made (an Always on one file of a
 *  send, alwaysSource), linked after the words as Undo it in Approvals. */
function keepAnswer(place, card, text, done = false, changeId = null) {
  if (!place) { showAskError(card, text, answerUndo(changeId)); return; }
  const id = card.dataset.id;
  const state = card.dataset.state || '';
  S.answers.set(place + ' ' + id, { place, id, state, text, done, changeId });
  const list = document.getElementById(ANSWER_PLACES[place]);
  const now = card.isConnected ? card : drawnCards(list).get(id);
  const shown = !!now && (now.dataset.state || '') === state;
  if (shown) showAnswer(now, { text, done, changeId });
  focusAnswered(place, id, list, shown && !done ? now : null);
}
function showAnswer(card, a) {
  if (a.done) letDone(card, a.text, answerUndo(a.changeId));
  else showAskError(card, a.text);
}
/** The link to the rule change an answer made, at its Rule changes row
 *  with its Undo (changesLink); null without one (an older server). */
function answerUndo(changeId) {
  return changeId ? changesLink(changeId, 'Undo it in Approvals') : null;
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
  putAnswerLine(place, list);
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
/** A real value shown hides itself again (dashboard.md §4.25b *The page*):
 *  a minute after it shows, at once when the tab goes to the background.
 *  Each open box: its button → its timer and its `hide`, which empties the
 *  box as Hide it again does and never moves the focus. */
const REVEAL_MS = 60_000;
const REVEAL_SOON_MS = 10_000;
const HIDE_SOON = 'Hides again in 1 minute.';
const HIDE_NOW = 'Hides again in a few seconds.';
const HIDES = new Map();
/** Hide the box of `btn` later; `say` puts when in its caption. */
function hideRevealLater(btn, hide, say) {
  stopHideLater(btn);
  if (!HIDES.size) document.addEventListener('visibilitychange', hideRevealsAway);
  say(HIDE_SOON);
  const at = { hide, timer: 0 };
  at.timer = setTimeout(() => {
    say(HIDE_NOW);
    at.timer = setTimeout(() => hideRevealNow(btn), REVEAL_SOON_MS);
  }, REVEAL_MS - REVEAL_SOON_MS);
  HIDES.set(btn, at);
}
/** Hide it again pressed, or a redraw: the timer of `btn` goes. */
function stopHideLater(btn) {
  const at = HIDES.get(btn);
  if (!at) return;
  clearTimeout(at.timer);
  HIDES.delete(btn);
  if (!HIDES.size) document.removeEventListener('visibilitychange', hideRevealsAway);
}
function hideRevealNow(btn) {
  const at = HIDES.get(btn);
  stopHideLater(btn);
  // A box a redraw took off the page is gone with its value.
  if (at && btn.isConnected) at.hide();
}
/** Another tab, a minimised window, a locked screen: every value goes. */
function hideRevealsAway() {
  if (document.visibilityState === 'hidden') for (const btn of [...HIDES.keys()]) hideRevealNow(btn);
}
/** The story is drawn again from nothing: no timer outlives its box. */
function stopHidesLater() {
  for (const btn of [...HIDES.keys()]) stopHideLater(btn);
}
/** The room the window keeps above what it scrolls into view, in px: the
 *  room of the top bar while it stays in sight on a wide window (app.css
 *  `scroll-padding-top`, dashboard.md §4.25 *The bar stays in sight on a
 *  wide window*), else the 8 px a phone keeps above what it lands. What
 *  lies above it is under the bar, or at the window's very edge, not in
 *  view. */
function barRoom() {
  return parseFloat(getComputedStyle(document.documentElement).scrollPaddingTop) || 0;
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
 *  the line the answer left where the card was (answerLine), else the card
 *  that took its place, else the one before it; with none left, the list's
 *  own line ("Nothing is waiting for you."), else the heading of its
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
  const line = S.answerLines.get(f.place);
  const to = same || (line && line.id === f.id && shown(line.node) ? line.node : null)
    || cards[Math.min(f.rank, cards.length - 1)]
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
 *  words that name a card: nameBy, the text of a reply: foldReply) are
 *  no keys, nor is a menu's colour (a rule's `data-effect`, a label menu's `data-level`, `data-send` and
 *  `data-from`: what the menu shows, not which it is). A menu
 *  with a name reads as its name, not its options: a change in it changes
 *  what it shows (a rule's "What happens for <host>" turned from allowed to
 *  blocked), not which menu it is; the Copy of a code block reads as Copy
 *  while it says Copied. While an answer holds the focus
 *  (holdFocus), it says where the focus goes, so the poll takes no place. */
const DRAWN_ID = /^(help|ask-error|ask-name|reply-text)-\d+$/;
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
  if (x.classList.contains('code-copy')) return 'BUTTON code-copy';
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
//   /scan  /plugins       the last scan (§4.25ai); where Mandu is attached as
//                         a plugin (§4.25aj)
//   /history?q=<words>    History found by a search (*Finding a session*);
//                         `&only=stepped-in` (or `?only=`) keeps the sessions
//                         where Mandu stepped in
//   /agents/<sessionId>   the agent page; `?ask=<askId>` marks a moment,
//                         `?only=stepped-in` shows only where Mandu stepped in
//   /approvals#<key>  /rules#<key>  /settings#<key>  that page at one of
//                         its cards (SECTIONS)
//   /rules?file=<path>    Rules with Add a rule's file browser opened at one
//                         file (a Your secrets card's or a scan finding's
//                         link); dropped once used
// A path names the resource, the query only view state (the agent page's
// mark, History's search). Segments are encodeURIComponent-written and decoded on read.
const PAGES = ['home', 'approvals', 'rules', 'settings', 'agent', 'history', 'scan', 'plugins'];
/** The `?only=` of the agent page's switch and History's (§4.25ae *Only
 *  where Mandu stepped in*, *Only the sessions where Mandu stepped in*);
 *  any other value reads as off. */
const ONLY_STEPPED_IN = 'stepped-in';
/** The cards of Approvals, Rules and Settings, each with its address
 *  (dashboard.md §4.25 *Section links*): `[key, the card's id, the words of
 *  its link, whether the card can hide]`. The row under each page's title
 *  links them in this order, and `/rules#<key>` opens Rules at that card.
 *  A card that can hide (while empty, or Settings' Dashboard account while
 *  this browser is not signed in) has no link while hidden
 *  (followSectionLinks). */
const SECTIONS = {
  // The questions an agent waits on before Keys Mandu found, which is advice
  // (2026-10-26).
  approvals: [
    ['asked-for', 'approvals-proposals-block', 'Rule changes asked for', true],
    ['waiting', 'approvals-waiting-block', 'Waiting'],
    ['keys-found', 'approvals-suggestions-block', 'Keys Mandu found', true],
    ['answered', 'approvals-answered-block', 'Answered earlier'],
    ['rule-changes', 'approvals-rule-history-block', 'Rule changes', true],
  ],
  rules: [
    ['describe', 'describe-block', 'Describe'],
    ['your-rules', 'rules-block', 'Your rules'],
    ['who', 'by-who-block', 'Who may get your secrets'],
    ['made-from', 'made-from-block', 'Files made from your secrets', true],
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
    // Sign out, shown only to a browser signed in on the sign-in page
    // (renderSignIn); its link hides with it (2026-11-04).
    ['account', 'settings-account-block', 'Dashboard account', true],
    ['about', 'settings-about-block', 'About'],
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
const PAGE_NAMES = { home: 'Home', approvals: 'Approvals', rules: 'Rules', settings: 'Settings', agent: 'Agent', history: 'History', scan: 'Scan', plugins: 'Plugins' };
const enc = encodeURIComponent;

/** The URL (absolute, under the base path) of a page; `id` is the agent
 *  page's session, the approvals page's question or the file Rules opens
 *  (`?file=`, its `/` kept as written), `ask` the agent page's marked
 *  moment, `go` where the agent page goes once drawn (`?go=`, AGENT_GO),
 *  `turn` the turn it lands on (`?turn=`, a turn's time, turnLink).
 *  An agent page with no session is Home. */
function routeHref(page, id, ask, go, turn) {
  if (page === 'approvals') return BASE + '/approvals' + (id ? '/' + enc(id) : '');
  if (page === 'rules' && id) return BASE + '/rules?file=' + enc(id).replace(/%2F/g, '/');
  if (page === 'rules' || page === 'settings' || page === 'history' || page === 'scan' || page === 'plugins') return BASE + '/' + page;
  if (page === 'agent' && id) return BASE + '/agents/' + enc(id) + (ask ? '?ask=' + enc(ask) : turn ? '?turn=' + enc(turn) : AGENT_GO.includes(go) ? '?go=' + go : '');
  return BASE + '/';
}
/** Where a link opens an agent page (`?go=`, a Home count's link; §4.25 *A
 *  tile takes you to what it counts*): its blocked or sent steps, as the
 *  tile's press, Your secrets, its newest turn as Latest turn goes (the
 *  "last step" of a running row, §4.25 *A live row names its last step*),
 *  Needs your OK as the waiting tile goes (the "1 question waiting
 *  for you" of a session row, waitingLink), or Changes Mandu did not
 *  apply to your files (the "changes to 1 file not applied" of an ended
 *  row, notAppliedLink). */
const AGENT_GO = ['blocked', 'sent', 'secrets', 'latest', 'waiting', 'not-applied'];
/** A turn's id from `?turn=` (§4.25 *A turn's time links to that turn*):
 *  the server's own (`turn:input:<event>:<n>`), so printable, with no
 *  space, up to 256 characters; anything else names no turn. */
function turnParam(v) {
  return typeof v === 'string' && /^[^\s\u0000-\u001f\u007f]{1,256}$/.test(v) ? v : null;
}

/** The page a URL names: { page, session, ask } (on Approvals `ask` is the
 *  question, the rule change or the change made it opens at), and on
 *  Approvals with none, Rules and Settings the card its hash names
 *  (`section`, only a key SECTIONS knows; one item opened wins); on Rules
 *  a non-empty `?file=` is the file Add a rule opens at (`file`), which
 *  wins over a card; on an agent page a known `?go=` is where it goes once
 *  drawn (`go`, AGENT_GO) and a well-formed `?turn=` the turn it lands
 *  on (`turn`, turnParam). A retired
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
  if (first === 'approvals' && second === undefined) {
    // The search of Answered earlier (§4.25 *Finding an answer*), if any,
    // and that of Rule changes (*Finding a rule change*).
    // And the day it lists from (*Go to a day on Answered earlier*), and
    // that of Rule changes (*Go to a day on Rule changes*).
    const words = historyQuery(q.get('q'));
    const changes = historyQuery(q.get('changes'));
    const day = historyDayParam(q.get('day'));
    const cday = historyDayParam(q.get('cday'));
    const section = sectionOf(first, hash);
    return { page: 'approvals', session: null, ask: null, ...(words ? { q: words } : {}), ...(day ? { day } : {}), ...(changes ? { changes } : {}), ...(cday ? { cday } : {}), ...(section ? { section } : {}) };
  }
  if (first === 'approvals' && second) return { page: 'approvals', session: null, ask: second };
  if (first === 'scan' && second === undefined) {
    // The row the earlier leak of a session card opens (`?item=f3`, §4.25ai
    // *Where the real value is now*), used once.
    const item = scanItemParam(q.get('item'));
    return { page: first, session: null, ask: null, ...(item ? { item } : {}) };
  }
  if (first === 'plugins' && second === undefined) return { page: first, session: null, ask: null };
  if (first === 'history' && second === undefined) {
    const day = historyDayParam(q.get('day'));
    return { page: first, session: null, ask: null, q: historyQuery(q.get('q')), ...(q.get('only') === ONLY_STEPPED_IN ? { only: true } : {}), ...(day ? { day } : {}) };
  }
  if ((first === 'rules' || first === 'settings') && second === undefined) {
    const file = first === 'rules' ? q.get('file') || '' : '';
    if (file) return { page: first, session: null, ask: null, file };
    // The row of a remembered answer (`#answer-<id>`, Kept in Rules on Approvals).
    const answer = first === 'rules' ? answerInHash(hash) : null;
    if (answer) return { page: first, session: null, ask: null, answer };
    const section = sectionOf(first, hash);
    return { page: first, session: null, ask: null, ...(section ? { section } : {}) };
  }
  if (first === 'agents' && second) {
    const go = q.get('go');
    const turn = turnParam(q.get('turn'));
    return { page: 'agent', session: second, ask: q.get('ask') || null, ...(q.get('only') === ONLY_STEPPED_IN ? { only: true } : {}), ...(AGENT_GO.includes(go) ? { go } : {}), ...(turn ? { turn } : {}) };
  }
  return home;
}
const currentRoute = () => parseRoute(location.pathname, location.search, location.hash);
/** The answer a Rules hash names (`#answer-<id>`, keptLink), or null. */
function answerInHash(hash) {
  const m = /^#?answer-(.+)$/.exec(String(hash || ''));
  if (!m) return null;
  try { return decodeURIComponent(m[1]) || null; } catch { return null; }
}

/** The URL a page state is canonically at. */
function stateHref() {
  if (S.page === 'agent') {
    const href = routeHref('agent', S.agentId, S.agentAsk, null, S.agentTurn);
    return S.agentOnly ? href + (href.includes('?') ? '&' : '?') + 'only=' + ONLY_STEPPED_IN : href;
  }
  if (S.page === 'approvals') {
    const finds = S.approvalsAsk ? [] : [S.answeredQ ? 'q=' + enc(S.answeredQ) : '', S.answeredDay ? 'day=' + S.answeredDay : '', S.changesQ ? 'changes=' + enc(S.changesQ) : '', S.changesDay ? 'cday=' + S.changesDay : ''].filter(Boolean);
    return routeHref('approvals', S.approvalsAsk) + (finds.length ? '?' + finds.join('&') : '') + (S.section && !S.approvalsAsk ? '#' + S.section : '');
  }
  if (S.page === 'history' && (S.historyQ || S.historyOnly || S.historyDay)) return routeHref('history') + '?' + historyParams(S.historyQ, S.historyOnly, S.historyDay);
  if (S.section && SECTIONS[S.page]) return routeHref(S.page) + '#' + S.section;
  return routeHref(S.page);
}

/** `nav`: a page change the person made (a link, Back or Forward), which
 *  moves the focus to the page (focusPage); not the first load. `restore`:
 *  the place Back or Forward returns to (savePlace; dashboard.md §4.25
 *  *Back and Forward keep your place*), which History, Approvals, Home,
 *  Rules, Settings and Scan return to; a link starts the page at its top. `land`: where a link opens
 *  its page (a page's own address says it otherwise): on Rules the file
 *  (`data-file`), on an agent page where it goes (`data-land`, AGENT_GO),
 *  on History its switch on (`data-land="stepped-in"`). */
function setPage(page, push, sessionId, askId, nav = push, restore = null, land = null) {
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
  // A link may open History found by a search (`data-land` "q:<words>": a
  // card on Plugins, "Its sessions on History", §4.25aj).
  const landQ = push && typeof land === 'string' && land.startsWith('q:') ? historyQuery(land.slice(2)) : '';
  S.historyQ = S.page === 'history' ? (push ? landQ : currentRoute().q || '') : '';
  if (S.page === 'history') document.getElementById('history-q').value = S.historyQ;
  // So does the search of Answered earlier (§4.25 *Finding an answer*), but never with
  // an answer the address opens (`/approvals/<id>`): the row it marks is
  // never filtered out.
  clearTimeout(answeredSearchTimer);
  // A link may open it found by a search too (`data-land` "q:<words>": a
  // host that Check a host on Rules names, §4.25aa *Check a host*).
  S.answeredQ = S.page === 'approvals' && !S.approvalsAsk ? (push ? landQ : currentRoute().q || '') : '';
  document.getElementById('answered-q').value = S.answeredQ;
  // And its day (§4.25 *Go to a day on Answered earlier*): kept by Back,
  // Forward, a reload and a typed address, as the day of History; a link
  // opens Approvals at the newest, and an answer the address opens drops
  // it, as it drops the search.
  S.answeredDay = S.page === 'approvals' && !S.approvalsAsk && !push ? currentRoute().day || '' : '';
  showAnsweredDay();
  if (S.answeredQ || S.answeredDay) document.getElementById('answered-search').hidden = false;
  // And the search of Rule changes (§4.25 *Finding a rule change*): kept by
  // Back, Forward and a typed address, never with a change the address
  // opens, whose marked row it would filter out. A link opens it empty but
  // the one under a rule (`data-land` "changes:<words>", originLine), which
  // lands at the card.
  clearTimeout(changesSearchTimer);
  const landChanges = push && S.page === 'approvals' && !S.approvalsAsk && typeof land === 'string' && land.startsWith('changes:') ? historyQuery(land.slice(8)) : '';
  S.changesQ = S.page === 'approvals' && !S.approvalsAsk ? (push ? landChanges : currentRoute().changes || '') : '';
  document.getElementById('changes-q').value = S.changesQ;
  // And its day (§4.25 *Go to a day on Rule changes*), as that of Answered
  // earlier: kept by Back, Forward, a reload and a typed address; a link
  // opens Rule changes at the newest, and a change the address opens drops
  // it, so its marked row is listed.
  S.changesDay = S.page === 'approvals' && !S.approvalsAsk && !push ? currentRoute().cday || '' : '';
  showChangesDay();
  if (S.changesQ || S.changesDay) document.getElementById('changes-search').hidden = false;
  // And its switch (§4.25ae *Only the sessions where Mandu stepped in*).
  // A link opens it off, unless it is a link to the switch (a Home count's,
  // §4.25 *The counts link where they point*).
  S.historyOnly = S.page === 'history' && (push ? land === ONLY_STEPPED_IN : currentRoute().only === true);
  if (S.page === 'history') document.getElementById('history-only').setAttribute('aria-checked', String(S.historyOnly));
  // And its day (§4.25ae *Go to a day*): kept by Back, Forward, a reload
  // and a typed address; a link opens History at the newest.
  S.historyDay = S.page === 'history' && !push ? currentRoute().day || '' : '';
  if (S.page === 'history') showHistoryDay();
  // An address with a search, the switch or a day has its box at once,
  // though the record was empty when last drawn (§4.25ae *An empty History
  // has nothing to find*).
  if (S.page === 'history' && (S.historyQ || S.historyOnly || S.historyDay)) document.getElementById('history-search').hidden = false;
  // So does the agent page's switch (§4.25ae *Only where Mandu stepped in*):
  // a link to a session opens it whole.
  S.agentOnly = S.page === 'agent' && !push && currentRoute().only === true;
  // And the card of Approvals, Rules or Settings (§4.25 *Section links*): a typed address,
  // a new tab or a Back with no place opens at the card its hash names (a
  // place Back hands back wins, landAtSection); a link opens the page at
  // its top (openAtCard names its card after).
  S.section = SECTIONS[S.page] && !push ? currentRoute().section || null : landChanges ? 'rule-changes' : null;
  // And the file a Your secrets card opens Rules at (§4.25b *A card opens
  // its file in Rules*): a link's, else the address's. Used once: the
  // canonical replace below drops `?file=`, so a reload or a later visit
  // does not open it again.
  const rulesFile = S.page === 'rules' ? (push ? land : currentRoute().file) || null : null;
  // And the Scan row the earlier leak of a card opens (`data-land` "item:f3",
  // or `?item=` in the address), used once as `?file=` is.
  const scanItemTo = S.page === 'scan' ? (push ? scanItemParam(typeof land === 'string' && land.startsWith('item:') ? land.slice(5) : null) : currentRoute().item) || null : null;
  // And the answer Kept in Rules names (`#answer-<id>`, §4.25 *A remembered
  // answer opens where Rules keeps it*), used once as `?file=` is. A link on
  // the page opens it itself (openAnswerRule); its note goes with the page.
  const rulesAnswer = S.page === 'rules' && !push ? currentRoute().answer || null : null;
  hideAnswerNote();
  // And where an agent page goes once drawn (§4.25 *A tile takes you to
  // what it counts*, `?go=`): used once, after the visit's first draw
  // (landGo); the canonical replace below drops it from the address.
  const go = S.page === 'agent' ? (push ? land : currentRoute().go) : null;
  // And the turn its address names (§4.25 *A turn's time links to that
  // turn*, `?turn=`): kept in the address as a fragment is, landed on once
  // a visit (landGo). A link opens the page without it; an ask's moment wins.
  S.agentTurn = S.page === 'agent' && !push && !S.agentAsk ? currentRoute().turn || null : null;
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
  if (push) history.pushState(pushedState(left), '', href);
  else if (at !== href) history.replaceState(history.state, '', href);
  S.pageTitle = S.page === 'home' ? 'Mandu' : 'Mandu · ' + PAGE_NAMES[S.page];
  renderTitle();
  // The page of a session opened at the moment of an ask (`?ask=`) is not: it
  // lands on the ask as a link does (markFocus).
  const back = restore && PLACE_PAGES.includes(S.page) && !(S.page === 'agent' && S.agentAsk) ? restore : null;
  window.scrollTo(0, back ? back.y || 0 : 0);
  S.visit++;
  dropAnswerLines();
  // A place Back hands back wins over the turn of the address.
  S.agentGo = AGENT_GO.includes(go) ? { visit: S.visit, kind: go } : S.agentTurn && !back ? { visit: S.visit, kind: 'turn', turn: S.agentTurn } : null;
  // Back to the page of a session: what Show them brought is asked for
  // again by its first read, and the toggles you had opened and the turn
  // you were reading wait for the draw of that read (drawAgentPage,
  // agentLandPlace).
  S.agentPlace = null;
  if (back && S.page === 'agent') {
    const place = { y: back.y || 0, ...agentPlaceOf(back) };
    S.agentShow = { key: S.visit + ':' + S.agentId, ...place.show };
    S.agentPlace = { visit: S.visit, id: S.agentId, place, at: window.scrollY };
  }
  // Held until the page has landed there: a scroll on the way (the page
  // shorter until its read draws) is not the place.
  S.placeHeld = back ? S.visit : 0;
  // Back to Approvals keeps the place you left, not that of its marked
  // card (markApprovalsAsk still gives the card the focus).
  S.approvalsPlace = !!back && S.page === 'approvals';
  if (S.page === 'agent') agentBack();
  if (nav) focusPage();
  // Approvals, Rules and Settings return their reads, done once drawn: a
  // link to one of their cards scrolls there then (openAtCard). Rules' include the folder
  // Add a rule opens with on its first read, when it was left open.
  let load = null;
  if (S.page === 'rules') load = loadRules().then(() => F.listing);
  if (S.page === 'rules') describeWhere();
  if (rulesFile) landAtFile(load, rulesFile);
  else if (rulesAnswer) landAtAnswer(load, rulesAnswer);
  // A link to Approvals starts its lists of the past over at their newest
  // 20, as a link to History does; Back keeps the rows you had brought.
  if (S.page === 'approvals' && !back) startPastOver();
  if (S.page === 'approvals') answeredSearchNow();
  // Rule changes is the last read of Approvals: a card its address names
  // waits for it (landAtSection), as a place Back hands back does.
  if (S.page === 'approvals') { load = loadRuleHistory(); keepPlace(load, back); }
  if (landChanges) landAtCard(load, 'approvals-rule-history-block');
  if (S.page === 'approvals' && S.home) markApprovalsAsk();
  if (S.page === 'settings') load = loadSettings();
  // Back to Rules or Settings: where you were once its reads have drawn,
  // never the card its address names (landAtSection).
  if (S.page === 'rules' || S.page === 'settings') keepPlace(load, back);
  if (S.page === 'agent') loadAgent();
  if (S.page === 'history') loadHistory(false, back);
  if (S.page === 'scan') load = loadScan();
  // Back to Scan: the sections, rows and folds you had open, then your
  // place (scanLandPlace); a place Back hands back wins over a row the
  // address names.
  if (S.page === 'scan' && back) scanLandPlace(load, back);
  else if (scanItemTo) landAtScanItem(load, scanItemTo);
  // Back to Plugins: where you were once its one read has drawn.
  if (S.page === 'plugins') { load = loadPlugins(); keepPlace(load, back); }
  if (S.page === 'home') keepPlace(null, back);
  return load;
}
/** An address that names a card (§4.25 *Section links*: a typed address, a
 *  new tab, Back or Forward): the page lands there once `load`, what draws
 *  above the card, has drawn, as a link to it does (openAtCard), the focus
 *  on the card's heading. Not when Back or Forward handed the page a place
 *  (setPage holds it, placeHeld, until its reads have drawn): the person
 *  left the page there, and the place wins over the card. */
function landAtSection(load) {
  if (S.placeHeld && S.placeHeld === S.visit) return;
  const card = S.section && SECTIONS[S.page] && SECTIONS[S.page].find((x) => x[0] === S.section);
  if (!card) return;
  focusPage();
  landAtCard(load, card[1]);
}

/** Rules opened at a file (`/rules?file=`, a Your secrets card's or a scan
 *  finding's link; §4.25b *A card opens its file in Rules*): once the page's reads have
 *  drawn, Add a rule's file browser opens at the file's folder with its row
 *  opened, as Show in the file browser does, and the focus goes to the
 *  row's ⋯ (the path box when it is not listed: focusPicked). The focus
 *  moves only from the page (its heading, or none): one the person moved
 *  meanwhile stays. Nothing is changed: Rules' own menus and Save do that. */
async function landAtFile(load, file) {
  const visit = S.visit;
  try { await load; } catch { /* each card says what it could not read */ }
  if (S.visit !== visit || S.page !== 'rules') return;
  const now = document.activeElement;
  const ours = (!!S.pageHeading && now === S.pageHeading) || focusFell();
  if (ours) focusPage();
  setFilesView('all', { folder: parentOf(file), pick: file, by: ours ? document.activeElement : null });
}

/** The id of a Scan row as `?item=` names it (`f3`); anything else, null. */
function scanItemParam(v) {
  return typeof v === 'string' && /^f\d{1,6}$/.test(v) ? v : null;
}

/** The most pages a link to a Scan row reads on for it (landAtScanItem). */
const SCAN_LAND_READS = 40;
/** Open the Scan page at one row (§4.25ai *A session card opens its row*):
 *  once its read has drawn, the fold of the row opens (its places and examples
 *  are read then) and the row comes into view with the focus. A row past
 *  the first page of *Your secrets that reached the AI* (the section a
 *  link names, scanItemIdOf) is read on to first, a page at a time with
 *  the section's own Show more (scanReadTo). A row its section does not
 *  have once it ends (a newer scan changed the list), or a page that could
 *  not be read, is said in a line under the headline (`#scan-item-missing`)
 *  and the page stays at its top. Reading on took a while: a person who
 *  scrolled or moved the focus meanwhile keeps both (the row still opens). */
async function landAtScanItem(load, id) {
  const visit = S.visit;
  try { await load; } catch { /* the page says what it could not read */ }
  const here = () => S.visit === visit && S.page === 'scan';
  if (!here()) return;
  // `id` passed scanItemParam (f and digits): safe in the selector.
  const find = () => document.querySelector('#scan-sections .scan-item[data-id="' + id + '"]');
  let row = find();
  let take = true;
  if (!row) {
    const y = window.scrollY;
    const had = document.activeElement;
    const got = await scanReadTo(here, Number(id.slice(1)));
    if (!here()) return;
    row = got.drawn ? find() : null;
    if (!row) return scanItemMissing(got);
    take = window.scrollY === y && (document.activeElement === had || focusFell());
  }
  const sec = row.closest('details.scan-fold');
  if (sec) sec.open = true;
  const fold = row.querySelector('details.scan-more');
  if (fold && !fold.open) { fold.open = true; fold.dispatchEvent(new Event('toggle')); }
  if (!take) return;
  row.setAttribute('tabindex', '-1');
  row.focus({ preventScroll: true });
  if (row.scrollIntoView) row.scrollIntoView({ block: 'start' });
}
/** Reads *Your secrets that reached the AI* on, a page at a time with its
 *  own Show more, until its row `k` (`f<k>`) is drawn: at most k + 1 rows
 *  and SCAN_LAND_READS reads, with scroll anchoring off meanwhile
 *  (scanAnchorOff). Stops once `here()` is not (another visit or page) or
 *  the section is drawn again (a part of another scan answered 409, a
 *  poll's new scan). Says how it ended: `drawn` (the row is in the
 *  section's rows), `ended` (the section has no more pages), `failed`
 *  (its last read failed; `failure` its cause, null when unknown), or none
 *  of them (stopped). */
async function scanReadTo(here, k) {
  // Compared as values, never spliced into a selector: ids are server data.
  const box = [...document.querySelectorAll('#scan-sections > .scan-section')].find((b) => b.dataset.section === 'yours');
  const sec = box && SCAN_SECTION.get(box);
  if (!sec) return { drawn: false, ended: false, failed: false, failure: null };
  const anchorOn = scanAnchorOff(S.visit);
  try {
    let reads = 0;
    while (here() && box.isConnected && sec.drawn() <= k && reads < SCAN_LAND_READS) {
      reads++;
      if (!await sec.more()) break;
    }
    if (!here() || !box.isConnected) return { drawn: false, ended: false, failed: false, failure: null };
    const drawn = sec.drawn() > k;
    return { drawn, ended: !drawn && sec.ended(), failed: !drawn && sec.failed(), failure: sec.failure() };
  } finally { anchorOn(); }
}
/** The line under the Scan page's headline for a link whose row it could
 *  not open (landAtScanItem): gone from the list, or a page unread; a stop
 *  for another reason says nothing. */
function scanItemMissing(got) {
  const line = document.getElementById('scan-item-missing');
  if (!line || !(got.ended || got.failed)) return;
  clear(line);
  if (got.ended) line.textContent = 'That secret is not in the last scan\'s list any more. A newer scan may have changed it.';
  else line.append(...cannotCheck('The page could not read on to that secret.', got.failure, true));
  line.hidden = false;
}
/** Scroll anchoring off while the Scan page reads on for `visit`
 *  (scanLandPlace, scanReadTo), so the rows it adds do not move the page
 *  as a person would; the function it returns turns it back on, once, if
 *  no later landing took it over. Off on both: Chromium reads the
 *  viewport's from <body>, the spec from the scroller's (<html>). */
function scanAnchorOff(visit) {
  const roots = [document.documentElement, document.body];
  SC.landing = visit;
  for (const r of roots) r.style.overflowAnchor = 'none';
  return () => {
    if (SC.landing !== visit) return;
    SC.landing = 0;
    for (const r of roots) r.style.removeProperty('overflow-anchor');
  };
}

// ── Back and Forward keep your place (dashboard.md §4.25) ────────────────────
/** The pages Back and Forward return to where you left them: every page
 *  (Plugins since 2026-10-31). A link to one starts at its top. */
const PLACE_PAGES = ['history', 'approvals', 'home', 'agent', 'rules', 'settings', 'scan', 'plugins'];
/** Writes the place of the page shown into its own history entry, which Back or
 *  Forward hands back (popstate): how far it was scrolled (`y`), how many
 *  History rows were loaded (`rows`) and the session whose agent page it
 *  opened (`opened`, kept from the last push when not given). On the page of
 *  a session, once drawn this visit, also the turn you were reading and how far
 *  down the screen it was (`turn`, `top`: a running session gains turns, and
 *  past its cap the oldest drops off), the toggles you had opened (`story`,
 *  storyToggles) and what Show them brought (`show`, agentShow). On the
 *  Scan page, once drawn this visit, the sections and row folds you had
 *  opened and the rows each section had drawn (`scan`, scanPlace). Rules
 *  with text in Find a rule keeps its top, and so does Scan with text in a
 *  Find one: Find is never kept (Rules': setPage empties it; Scan's: the
 *  page draws anew), and a place in the shorter list would land elsewhere
 *  in the whole one. A browser that refuses the write (too many) keeps the
 *  last one. */
function savePlace(opened) {
  const st = history.state && typeof history.state === 'object' ? history.state : {};
  const had = st.place || {};
  // Still landing on a place Back gave (placeHeld): that place stays, only
  // the session a push opens is new.
  const held = !!S.placeHeld && S.placeHeld === S.visit;
  if (held && opened === undefined) return;
  const scan = S.page === 'scan' && !held ? scanPlace() : null;
  const place = {
    y: held ? had.y || 0 : (S.page === 'rules' && findText()) || (scan && scan.found) ? 0 : Math.round(window.scrollY || 0),
    rows: held ? had.rows || 0 : S.page === 'history' && S.history ? S.history.rows.length : 0,
    opened: opened === undefined ? had.opened || null : opened,
  };
  if (S.page === 'agent') Object.assign(place, held ? agentPlaceOf(had) : agentPlace());
  if (S.page === 'scan') place.scan = held ? scanPlaceOf(had.scan) : scan.scan;
  try { history.replaceState({ ...st, place }, ''); } catch { /* the last place stays */ }
}
/** The Scan page part of its place, read off the page (savePlace): the
 *  section folds open (`open`, by `data-section`), how many rows each
 *  section has drawn (`rows`, [id, n] pairs) and the rows whose *Details
 *  and examples* is open (`more`, by `data-id`); `found`: some *Find one*
 *  has text, whose section keeps only its fold (its rows answer the query,
 *  never kept). Nothing before the page's first draw this visit, which
 *  would read the last visit's. */
function scanPlace() {
  if (SC.drawn !== S.visit) return { found: false, scan: null };
  const scan = { open: [], rows: [], more: [] };
  let found = false;
  for (const box of document.querySelectorAll('#scan-sections > .scan-section')) {
    const sec = SCAN_SECTION.get(box);
    if (!sec) continue;
    const id = box.dataset.section;
    const fold = box.querySelector('details.scan-fold');
    if (fold && fold.open) scan.open.push(id);
    if (sec.found()) { found = true; continue; }
    scan.rows.push([id, sec.drawn()]);
    for (const f of box.querySelectorAll('.scan-item details.scan-more[open]')) scan.more.push(f.closest('.scan-item').dataset.id);
  }
  return { found, scan };
}
/** The Scan page part of a place as an entry holds it, its shape checked
 *  (agentPlaceOf's reason). */
function scanPlaceOf(p) {
  const ids = (x) => (Array.isArray(x) ? x.filter((v) => typeof v === 'string') : []);
  const s = p && typeof p === 'object' ? p : {};
  return {
    open: ids(s.open),
    rows: (Array.isArray(s.rows) ? s.rows : []).filter((r) => Array.isArray(r) && typeof r[0] === 'string' && Number.isInteger(r[1]) && r[1] > 0).map((r) => [r[0], r[1]]),
    more: ids(s.more),
  };
}
/** Back to the Scan page, once its read has drawn (`load`, loadScan): each
 *  section fold you had open opens again, each section reads on, a page at
 *  a time with its own Show more, to the rows it had drawn (stopping at its
 *  end or a failed read), the row folds you had opened open again and their
 *  examples are read, and the page scrolls to `y`. It scrolls there as the
 *  page grows and once all is drawn, each time only if nobody scrolled
 *  since: the first mark is taken after the page has drawn (it drew from
 *  nothing, and the browser held the scroll above), and scroll anchoring is
 *  off meanwhile (`overflow-anchor`) so the rows it adds do not move the
 *  page as a person would. A section or row the read no longer has (a scan
 *  kept since) is skipped; a page drawn again meanwhile (a part of another
 *  scan answered 409, a poll's new scan) stops it. Then the place is the
 *  page's to keep again (placeHeld). */
async function scanLandPlace(load, back) {
  const visit = S.visit;
  const place = scanPlaceOf(back.scan);
  const anchorOn = scanAnchorOff(visit);
  const here = () => S.visit === visit && S.page === 'scan';
  let at = null;
  const keep = () => {
    if (at === null || !here()) return;
    if (window.scrollY !== at) { at = null; anchorOn(); return; }
    window.scrollTo(0, back.y || 0);
    at = window.scrollY;
  };
  try {
    try { await load; } catch { /* the page says what it could not read */ }
    if (!here()) return;
    at = window.scrollY;
    keep();
    const reads = [];
    for (const box of [...document.querySelectorAll('#scan-sections > .scan-section')]) {
      const sec = SCAN_SECTION.get(box);
      if (!sec) continue;
      // Compared as values, never spliced into a selector: ids are server data.
      const id = box.dataset.section;
      const fold = box.querySelector('details.scan-fold');
      if (fold && place.open.includes(id)) fold.open = true;
      const want = (place.rows.find((r) => r[0] === id) || [id, 0])[1];
      while (here() && box.isConnected && sec.drawn() < want && await sec.more()) keep();
      if (!here() || !box.isConnected) return;
      for (const row of box.querySelectorAll('.scan-item')) {
        const more = place.more.includes(row.dataset.id) ? row.querySelector('details.scan-more') : null;
        if (!more) continue;
        more.open = true;
        const read = SCAN_FOLD_READ.get(more);
        if (read) reads.push(read());
      }
      keep();
    }
    await Promise.all(reads);
    keep();
  } finally {
    anchorOn();
    if (S.placeHeld === visit) S.placeHeld = 0;
  }
}
/** The session page part of its place, read off the page (savePlace):
 *  nothing before its first draw this visit, which would read the story of
 *  the visit before. */
function agentPlace() {
  if (S.agentDrawn !== S.visit + ':' + S.agentId) return {};
  const story = document.getElementById('agent-story');
  const anchor = [...story.querySelectorAll('article.turn[data-turn-id]')].find((t) => !t.closest('[hidden]') && t.getBoundingClientRect().bottom > 0);
  const { key, ...show } = agentShow();
  return {
    turn: anchor ? anchor.dataset.turnId : null,
    top: anchor ? Math.round(anchor.getBoundingClientRect().top) : 0,
    story: storyToggles(story),
    show: { ...show, steps: [...show.steps], background: [...show.background] },
  };
}
/** The session page part of a place as an entry holds it, its shape
 *  checked: the page wrote the entry itself, but a browser keeps it across
 *  versions of this script. */
function agentPlaceOf(p) {
  const strings = (x) => (Array.isArray(x) ? x.filter((v) => typeof v === 'string') : []);
  const s = p && p.story && typeof p.story === 'object' ? p.story : null;
  const sh = p && p.show && typeof p.show === 'object' ? p.show : {};
  return {
    turn: p && typeof p.turn === 'string' ? p.turn : null,
    top: p && Number.isFinite(p.top) ? p.top : 0,
    story: s ? {
      toggles: (Array.isArray(s.toggles) ? s.toggles : []).filter((x) => x && typeof x.turn === 'string' && Object.prototype.hasOwnProperty.call(STORY_TOGGLES, x.kind) && Number.isInteger(x.i))
        .map((x) => ({ turn: x.turn, kind: x.kind, i: x.i, open: x.open === true })),
      shown: typeof s.shown === 'string' ? s.shown : null,
      quiet: strings(s.quiet),
    } : null,
    show: { turns: sh.turns === true, secrets: sh.secrets === true, steps: strings(sh.steps), background: strings(sh.background) },
  };
}
/** Back to the page of a session, its first read drawn (renderAgentPage):
 *  the turn you were reading back at the height it had on the screen, else
 *  the `y` of the place, if nobody scrolled since the Back (the rule of
 *  keepPlace; the page, shorter until drawn, held it above). Once more after
 *  two frames, when the long replies above have folded (foldReply measures
 *  them as laid out), again only if nobody scrolled. Landed mid-page, the
 *  turn takes the focus from the heading, as the row of History does
 *  (historyLand). */
function agentLandPlace(kept) {
  const visit = S.visit;
  const land = () => {
    if (S.visit !== visit || window.scrollY !== kept.at) return null;
    // Compared as values, never spliced into a selector: ids are server data.
    const turn = kept.place.turn ? [...document.querySelectorAll('#agent-story article.turn[data-turn-id]')].find((t) => t.dataset.turnId === kept.place.turn && !t.closest('[hidden]')) : null;
    window.scrollTo(0, turn ? Math.max(0, Math.round(window.scrollY + turn.getBoundingClientRect().top - kept.place.top)) : kept.place.y || 0);
    kept.at = window.scrollY;
    return turn;
  };
  const turn = land();
  if (turn && kept.place.y > 0) focusMarked(turn, true);
  const done = () => { if (S.placeHeld === visit) S.placeHeld = 0; };
  if (S.visit !== visit || !turn) { done(); return; }
  requestAnimationFrame(() => requestAnimationFrame(() => { land(); done(); }));
}
/** Back to Approvals, Home, Rules, Settings or Plugins, once what the page
 *  reads has drawn (`read`: the rule changes of Approvals, every read of
 *  Rules, of Settings or of Plugins): scrolled again to the place, if a page shorter
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
/** The words of the back link of the agent page for the page it returns to:
 *  the name of the page (PAGE_NAMES, as the tab title has it), Home its own. */
const backTo = (page) => page === 'home' ? 'Back to home' : 'Back to ' + PAGE_NAMES[page];
/** A page Back can name (PAGE_NAMES) other than a session's own. */
const backPage = (page) => page !== 'agent' && typeof page === 'string' && Object.prototype.hasOwnProperty.call(PAGE_NAMES, page);
/** The state a pushed page change writes in its new entry (setPage): the
 *  page it left (`from`, agentBack). A step from one session's page to
 *  another (Newer, Older, any link between them) also carries the page the
 *  chain of session pages started from (`origin`, the left entry's own
 *  origin, else its `from`) and how many such steps it has taken (`depth`),
 *  so the back link still names that page and returns to it (§4.25ad *The
 *  back link names where you came from*). A chain with no page before it (a
 *  fresh tab, a typed address) carries neither. */
function pushedState(left) {
  if (left !== 'agent' || S.page !== 'agent') return { from: left };
  const st = history.state && typeof history.state === 'object' ? history.state : {};
  const chained = st.from === 'agent';
  const origin = chained ? st.origin : st.from;
  const depth = !chained ? 1 : Number.isInteger(st.depth) && st.depth > 0 ? st.depth + 1 : 0;
  return backPage(origin) && depth ? { from: 'agent', origin, depth } : { from: 'agent' };
}
/** The back link of the agent page names the page it was opened from in this
 *  tab (the entry before it, `from`), and returns there as Back does
 *  (wireNav), so that page keeps your place. Opened from another session's
 *  page, it names the page that chain started from (`origin`) and goes back
 *  `depth + 1` entries to it, a link instead when the tab no longer holds
 *  that many. Opened from a fresh tab, a typed address, or a chain of
 *  session pages that began there: "Back to home", a link Home. */
function agentBack() {
  const a = document.getElementById('agent-back');
  if (!a) return;
  const st = history.state && typeof history.state === 'object' ? history.state : {};
  const from = st.from;
  const chain = from === 'agent' && backPage(st.origin) && Number.isInteger(st.depth) && st.depth > 0;
  const to = chain ? st.origin : backPage(from) ? from : 'home';
  a.textContent = backTo(to);
  a.dataset.pageLink = to;
  a.href = routeHref(to);
  // The tab holds at least this entry's index + 1 entries: fewer than
  // `depth + 2` and the page the chain started from is not there to go back to.
  a.dataset.back = chain ? (history.length >= st.depth + 2 ? String(st.depth + 1) : '') : to === from ? '1' : '';
}
function wireNav() {
  document.addEventListener('click', (e) => {
    const a = e.target.closest('a[data-page-link]');
    if (!a) { rowClick(e); return; }
    if (e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    // The back link of the agent page, to the page before it in this tab, is
    // Back; at the end of a chain of session pages, as many Backs as it is long.
    if (a.id === 'agent-back' && a.dataset.back) {
      const n = Number(a.dataset.back);
      if (n > 1) history.go(-n);
      else history.back();
      return;
    }
    setPage(a.dataset.pageLink, true, a.dataset.session, a.dataset.ask || null, true, null, a.dataset.file || a.dataset.land || null);
  });
  document.getElementById('skip-link').addEventListener('click', skipToPage);
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
  const placeSoon = () => {
    clearTimeout(placeTimer);
    placeTimer = setTimeout(() => savePlace(), 250);
  };
  window.addEventListener('scroll', placeSoon, { passive: true });
  // A toggle of the story of a session moves nothing, and the Back of the
  // browser saves nothing on its way out: the click saves the place.
  document.getElementById('agent-story').addEventListener('click', placeSoon);
  // So does a fold of the Scan page, a section's or a row's (a toggle does
  // not bubble: heard on its way down).
  document.getElementById('scan-sections').addEventListener('toggle', placeSoon, true);
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
 *  the row (Details, the "last step" link of a running row, its "1 question
 *  waiting for you", the Preview and warning marks, their open note and its
 *  link) nor one that ends a text
 *  selection. The row stays no control: Details keeps its name and is its
 *  tab stop (with "last step" on a live row). One listener for every row,
 *  so a row keepRows keeps is no different. */
function rowClick(e) {
  const row = e.target.closest('.row.agent[data-session]');
  if (!row || e.target.closest('a, button, input, label, .help')) return;
  const sel = window.getSelection ? window.getSelection() : null;
  if (sel && String(sel).trim()) return;
  // Details, never the "last step" link before it in the row (which opens the
  // session at its newest turn).
  const link = row.querySelector('a.right[data-page-link="agent"]');
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
/** Skip to the page, the first Tab stop (dashboard.md §4.25 *A page change
 *  moves the focus*): the focus goes to the heading of the page shown, as a
 *  page change gives it, so the next Tab is the first control of the page,
 *  past the top bar. Never a jump to #main: the router reads a fragment as a
 *  new visit, and on Rules and Settings as a card to land at. So the address,
 *  the history and the page drawn stay; the window scrolls only to bring
 *  the heading into view when it is not (a page landed at a card). */
function skipToPage(e) {
  e.preventDefault();
  focusPage();
  const h = S.pageHeading;
  if (!h || !h.scrollIntoView) return;
  const b = h.getBoundingClientRect();
  if (b.top < barRoom() || b.bottom > window.innerHeight) h.scrollIntoView({ block: 'nearest' });
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
    // Mandu started since the last poll, which said it was not running at
    // all: as a return, what could not be read is read again.
    const wasOff = notRunningNow();
    S.home = answer;
    back = S.homeFailure !== null || (wasOff && !notRunningNow());
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
    renderAbout(null);
    renderFirstRun(null);
    renderHomeScan(null);
    renderHistoryScan(null);
    renderExposure(null);
    renderRouteLost(null);
    renderUpdateNotice(null);
    renderSecretsPosture(null);
    // Every section the answer fills says it could not check, never a bare
    // heading, nor the last poll's questions with live buttons (dashboard.md
    // §4.25 *Empty states*), each with the cause this poll knows. The open
    // agent page reads again, and says why it cannot show the session.
    renderHomeWaiting(null);
    renderAgents(null);
    renderEarlier(null);
    renderHomeMeanings();
    renderApprovals(null);
    markApprovalsAsk();
    followCannotCheck();
    renderTitle();
    refreshWhen();
    pollRefocus(place);
    if (S.page === 'agent' && !tabHidden()) loadAgent();
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
  followSaved();
  followRunningAnswers();
  renderHero(S.home);
  renderBuiltIn(S.home);
  renderAbout(S.home);
  renderFirstRun(S.home);
  renderHomeScan(S.home);
  renderHistoryScan(S.home);
  renderExposure(S.home);
  renderRouteLost(S.home);
  renderUpdateNotice(S.home);
  renderPolicyRefusedNotice(S.home);
  renderOpenPlacesNotice(S.home);
  renderRulesMark(S.home);
  renderSignIn(S.home);
  renderSecretsPosture(S.home);
  renderHomeWaiting(S.home);
  renderAgents(S.home);
  renderEarlier(S.home);
  renderHomeMeanings();
  renderApprovals(S.home);
  renderProposals();
  markApprovalsAsk();
  if (back) readAgainUnread();
  else { followCannotCheck(); if (F.unread === 'new') readFolderAgain(); }
  // A tab in the background reads Home for its notifications, title and
  // icon (§4.25 *A background tab keeps reading*); the reads only a person
  // looking at the page needs wait for its return, which reads at once.
  const hidden = tabHidden();
  if (S.page === 'approvals' && !hidden) { loadRuleHistory(); followAnswered(asked); }
  if (S.page === 'rules') { renameOriginLines(); followRules(asked); followHostWaiting(asked); }
  if (S.page === 'settings') followSettings(asked);
  if (S.page === 'history' && !hidden) followHistory(asked);
  // The empty row of History names the commands the Home answer brings
  // (`start`): drawn again when they changed (the poll of renderHistory compares).
  if (S.page === 'history' && S.history && S.history.drawn && !S.history.rows.length) renderHistory(document.getElementById('history-list'), true);
  // A Scan page drawn names the commands of the `start` of this answer: its two
  // sentences draw again when the list changed (§4.25ai).
  if (S.page === 'scan' && SC.vm && !SC.unread && !sameAsDrawn('scan-start', homeStart(S.home))) drawScanStart(SC.vm);
  // A Scan page whose read failed (the dashboard restarting, an answer cut
  // on its way) reads again once a poll answers (§4.25ai); one drawn reads
  // again when the card names another kept scan (scanFollows).
  if (S.page === 'scan' && SC.unread && !SC.reading && !hidden) loadScan();
  else if (S.page === 'scan' && !hidden && scanFollows(S.home && S.home.scan)) loadScan(true);
  // The Plugins page follows the service with each poll (§4.25aj): a proxy
  // that stops answering, an agent attached since.
  if (S.page === 'plugins' && !PL.reading && !hidden) loadPlugins();
  notifyNewAsks(S.home);
  // The screen-reader line waits too: its sets stay as they were, so the
  // first poll after the return says what arrived meanwhile.
  if (!hidden) announceNewAsks(S.home);
  renderTitle();
  refreshWhen();
  pollRefocus(place);
  if (S.page === 'agent' && !hidden) loadAgent();
}
/** The tab is in the background: behind another tab, in a minimised window,
 *  a locked screen. Not a page the browser is prerendering. */
function tabHidden() { return document.visibilityState === 'hidden'; }

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
  const asks = home.waitingKnown ? home.waiting : ['unknown', offKey()];
  if (sameAsDrawn('home-waiting', [asks, S.proposals.length, S.proposals.some((p) => p.onDisk), oneProposal(S.proposals),
    S.proposals.every(askedByAgent), proposalsAsker(S.proposals)])) return;
  renderAsks(host, home, false, S.proposals.length > 0, 'live first');
  putBackAnswers('home', host);
  renderHomeProposalLink();
}

/** Every question counted is from a session that has ended and no rule
 *  change waits (the hero's own rule): nothing is held up until you answer,
 *  so the count is drawn in grey, not the amber (§4.25 *The top bar's two
 *  marks*). One test for the top bar's badge and the tab's dot, so the two
 *  never disagree. */
function nothingHeldUp(home, waiting) {
  return waiting > 0 && S.proposals.length === 0 && home.waiting.every((a) => a.askerEnded);
}

function renderTopStatus(home) {
  const host = document.getElementById('top-status');
  const badge = document.getElementById('nav-approvals-count');
  const waiting = (home && home.waitingKnown ? home.waiting.length : 0) + S.proposals.length;
  badge.textContent = String(waiting);
  badge.hidden = waiting === 0;
  const ended = nothingHeldUp(home, waiting);
  badge.classList.toggle('ended', ended);
  // The link's name says what the count counts (§4.25 *The top bar's two
  // marks*), as the name of the Rules link does: a bare "2" said nothing
  // to a screen reader. Written only when the count or its grey changed,
  // never every poll.
  if (!sameAsDrawn('approvals-mark', [waiting, ended])) {
    const link = badge.parentElement;
    if (waiting) {
      const name = !ended ? 'Approvals, ' + waiting + ' waiting for your answer'
        : waiting === 1 ? 'Approvals, 1 question from a session that has ended, no agent is waiting on it'
          : 'Approvals, ' + waiting + ' questions from sessions that have ended, no agent is waiting on them';
      link.setAttribute('aria-label', name);
      link.title = name;
    } else {
      link.removeAttribute('aria-label');
      link.removeAttribute('title');
    }
  }
  // Home's summary of the Approvals page counts what the nav badge counts.
  const title = document.getElementById('home-waiting-title');
  if (title) title.textContent = waiting ? 'Approvals waiting (' + waiting + ')' : 'Approvals waiting';
  // A live region: written again only when what it says changed, never
  // every poll (§4.25 *The poll keeps your place*).
  const failed = home && home.verdict === 'failed' && !home.protection.notRunning ? [failedAt(home)] : null;
  if (sameAsDrawn('top-status', home ? [home.protection.level, home.protection.connected, home.protection.configured, !!home.protection.notRunning, failed] : 'failed')) return;
  clear(host);
  if (!home) {
    host.append(el('span', { class: 'dot bad' }), protectionLink('Not connected'));
    return;
  }
  // Mandu is not running at all (§4.25, *Protection is off when nothing runs*):
  // no agent is protected, so off, as the hero says; never "unknown".
  if (home.protection.notRunning) {
    host.append(el('span', { class: 'dot warn' }), protectionLink('Protection off'));
    return;
  }
  // Something reached the AI unmasked (§4.25 *The top bar says on or off*,
  // 2026-10-23): the hero's verdict, above off and a change for the next
  // start, as its ladder ranks it; on every page, a link to where it happened.
  if (failed) {
    host.append(el('span', { class: 'dot bad' }), failedLink(failed[0]));
    return;
  }
  // On or off, the words of the Settings switch (§4.25 *The top bar says on
  // or off*): the product offers no level to name. No protection service is
  // "Not connected", grey, as the hero and the tab say (2026-10-28); only a
  // service that answers without saying its level is "Protection unknown".
  const state = protectionState(home.protection.level);
  const cls = state === 'off' ? 'warn' : state === 'unknown' ? '' : 'ok';
  const words = state === 'unknown' && !home.protection.connected ? 'Not connected'
    : { on: 'Protection on', off: 'Protection off', unknown: 'Protection unknown' }[state];
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

/** The one session where protection failed, as the hero's sentence links it:
 *  its agent page (`agent`) or, in the developer build, its trace (`trace`).
 *  Null when the sentence's links name more than one session (the product
 *  build names each failed one since 2026-10-25, §4.25ad) or none (the
 *  developer build's trace list): the top bar then opens Home, whose hero
 *  and rows say which. It counts every `agent`/`trace` link of the `failed`
 *  sentence, so a hero that adds other such links keeps them apart (§4.25
 *  *It says when protection failed*). */
function failedAt(home) {
  const parts = Array.isArray(home.sentenceParts) ? home.sentenceParts : [];
  const sessions = new Set(parts
    .filter((x) => x && x.kind === 'link' && (x.to === 'agent' || x.to === 'trace') && typeof x.session === 'string' && x.session !== '')
    .map((x) => x.session));
  return sessions.size === 1 ? [...sessions][0] : null;
}

/** The top bar's words while protection failed: a link to the product's
 *  page of that session, or to Home, whose hero and rows say which, when
 *  several failed. A plain click opens it in place (wireNav). */
function failedLink(session) {
  const words = 'Protection failed';
  return session
    ? el('a', { href: routeHref('agent', session), class: 'top-status-link', 'data-page-link': 'agent', 'data-session': session, 'aria-label': words + ': open the session where it happened', text: words })
    : el('a', { href: routeHref('home'), class: 'top-status-link', 'data-page-link': 'home', 'aria-label': words + ': open Home', text: words });
}

/** A level as the product says it: off, unknown, or on (any level that
 *  protects). */
function protectionState(level) {
  return level === 'off' ? 'off' : (level === 'unknown' || !level) ? 'unknown' : 'on';
}

/** The Rules page "Built-in protections" (dashboard.md §4.25z): the list
 *  the server built for the mode running now, so the page never claims masking
 *  the mode does not do. Without the home, nothing is claimed. */
/** Built-in protections while Mandu is not running at all, as
 *  view-model/home.ts builtInProtections says it. */
const BUILT_IN_OFF = 'Mandu is not running now, so none of these is on. They turn on with your first agent.';
function renderBuiltIn(home) {
  const list = document.getElementById('builtin-list');
  const note = document.getElementById('builtin-note');
  if (!list || !note) return;
  const b = home && home.builtIn;
  const at = b && Number.isInteger(b.filesAt) ? b.filesAt : null;
  const files = at === null ? null : S.builtinFiles;
  if (at !== null && !files && S.page === 'rules') loadBuiltinFiles();
  // An older server sends no list: Mandu not running at all says so, as
  // the list of the server does (§4.25 *Protection is off when nothing runs*).
  const off = !b && !!home && !!home.protection && !!home.protection.notRunning;
  if (sameAsDrawn('built-in', b ? { b, files: !!files } : off)) return;
  clear(list);
  note.textContent = b ? b.note : off ? 'not running' : 'not connected';
  const items = b ? b.items : [off ? BUILT_IN_OFF : 'The protection service is not reachable, so Mandu cannot say what is on.'];
  const parts = b && Array.isArray(b.itemsParts) ? b.itemsParts : [];
  items.forEach((text, i) => {
    const li = el('li', {}, textParts(parts[i], text));
    if (files && at === i) filesFold(li, files);
    list.append(li);
  });
  if (b && b.issuers && typeof b.issuers === 'object') list.append(issuerItem(b.issuers));
}

/** The lists of the Which files fold: fixed copy, so the polled home leaves them
 *  out and the page reads them once (`home?files=1`, dashboard.md §4.25z),
 *  then draws the card again. A read that fails leaves the card as it was,
 *  and the next change of the card asks again. */
function loadBuiltinFiles() {
  if (S.builtinFilesLoading) return;
  S.builtinFilesLoading = true;
  apiGet('home?files=1').then((h) => {
    const f = h && h.builtIn && h.builtIn.files;
    if (f && typeof f === 'object') { S.builtinFiles = f; renderBuiltIn(S.home); }
  }, () => {}).finally(() => { S.builtinFilesLoading = false; });
}

/** Under "Keys and secret files reach the AI masked" (dashboard.md §4.25z):
 *  a closed **Which files** fold naming the files Mandu keeps secret with no
 *  rule of yours, every name as code: the kinds named so in any folder, the
 *  places in the home folder as one wrapped run, then how a rule of yours
 *  makes one readable. The page offers no switch. */
function filesFold(li, f) {
  const arr = (x) => (Array.isArray(x) ? x : []);
  const names = (row, list) => { list.forEach((n, i) => row.append(...(i ? [', ', ownCode(n)] : [ownCode(n)]))); return row; };
  li.classList.add('builtin-files');
  const body = [el('p', { class: 'builtin-files-head', text: 'Named like this, in any folder:' })];
  const kinds = el('ul', { class: 'plain-list builtin-kinds' });
  for (const k of arr(f.kinds)) {
    const row = names(el('li', {}, k.words + ': '), arr(k.names));
    if (k.where) row.append(' (' + k.where + ')');
    kinds.append(row);
  }
  body.push(kinds);
  if (arr(f.templates).length) body.push(names(el('p', { class: 'muted builtin-files-note' }, 'Templates are left out: '), arr(f.templates)));
  const places = arr(f.places);
  body.push(el('p', { class: 'builtin-files-head', text: 'These places in your home folder (' + places.length + ' places):' }));
  body.push(names(el('p', { class: 'builtin-places' }), places));
  if (arr(f.system).length) body.push(names(el('p', { class: 'builtin-places' }, 'And these system files: '), arr(f.system)));
  for (const a of arr(f.also)) body.push(el('p', { class: 'builtin-files-note' }, textParts(a.parts, a.text)));
  if (f.found) body.push(el('p', { class: 'builtin-files-note', text: f.found }));
  if (f.change) body.push(el('p', { class: 'muted builtin-files-change' }, textParts(f.change.parts, f.change.text)));
  li.append(el('details', { class: 'more' }, el('summary', { text: 'Which files' }), ...body));
}

/** The item for the built-in issuer bindings (dashboard.md §4.25z): its sentence,
 *  each company with its hosts as code under a "Which companies" fold, and
 *  how to change it as policy.yaml text. The page offers no switch. */
function issuerItem(it) {
  const li = el('li', { class: 'builtin-issuers', 'data-state': it.state });
  li.append(el('span', {}, textParts(it.parts, it.text)));
  const companies = Array.isArray(it.companies) ? it.companies : [];
  if (companies.length) {
    const ul = el('ul', { class: 'plain-list issuer-list' });
    for (const c of companies) {
      const row = el('li', {}, c.name + (c.off ? ' (asks)' : '') + ': ');
      (Array.isArray(c.hosts) ? c.hosts : []).forEach((h, i) => row.append(...(i ? [', ', ownCode(h)] : [ownCode(h)])));
      ul.append(row);
    }
    li.append(el('details', { class: 'more' }, el('summary', { text: 'Which companies' }), ul));
  }
  if (it.change) li.append(el('p', { class: 'muted issuer-change' }, textParts(it.change.parts, it.change.text)));
  return li;
}

/** Settings › About Mandu (dashboard.md §4.25 *About Mandu*): the release
 *  the dashboard runs and its four help links, from Home's `about`, drawn
 *  on every page's poll so Settings opens with it, and drawn again only when
 *  it changed. "Checking…" (the page's own) until the first answer; a poll
 *  that fails keeps what an answer drew, and with none yet the row says how
 *  to find the version, as an unknown one does: never an empty row, never
 *  "Checking…" for good. Each link opens in a new tab with noopener
 *  noreferrer (the page's address can name a session), and only an https
 *  address is drawn as a link. Report a problem opens the bug form with
 *  the version filled in (`bugReportUrl`), or the issue list from an older
 *  server. */
function renderAbout(home) {
  const row = document.getElementById('settings-about-version');
  const links = document.getElementById('settings-about-links');
  const report = document.getElementById('settings-about-report');
  if (!row || !links || !report) return;
  const about = home && home.about && typeof home.about === 'object' ? home.about : null;
  if (!home && S.about) return;
  if (sameAsDrawn('about', about || 'none')) return;
  if (about) S.about = about;
  const v = about && typeof about.version === 'string' && about.version !== 'unknown' ? about.version : null;
  clear(row); clear(links); clear(report);
  if (v) row.textContent = 'Mandu ' + v;
  else row.append('Not known. Run ', runCode('mandu --version'), ' in a terminal.');
  // Whether a newer release is out (§4.25 *A newer release*): the answer
  // the launcher's last check left, or, with none, whether and when Mandu
  // checks.
  const up = v ? updateOf(about) : null;
  if (up && up.state !== 'unknown') row.append('. ', aboutUpdateNode(up, v));
  const check = document.getElementById('settings-about-check');
  if (check) {
    check.hidden = !(up && up.state === 'unknown');
    if (!check.hidden) { clear(check); check.append(...aboutCheckParts(up.check)); }
  }
  const said = v ? 'Say which version you run: Mandu ' + v + '.' : null;
  const https = (url) => typeof url === 'string' && /^https:\/\//.test(url);
  const link = (url, text, title) => https(url)
    ? el('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text, title }) : null;
  // Report a problem opens GitHub's bug form with the version filled in
  // (§4.25 *About Mandu*), the address the server built; an older server
  // sends none, and the issue list is drawn as before. The words say
  // "filled in" only when the address carries this version: one that is
  // not semver is left out of it (homeAbout).
  const form = !!about && https(about.bugReportUrl);
  const filled = form && v && formVersion(about.bugReportUrl) === v
    ? "Report a problem opens GitHub's bug form with your version, Mandu " + v + ', filled in.' : null;
  const problem = link(about && (form ? about.bugReportUrl : about.issuesUrl), 'Report a problem', filled || said);
  const shown = [
    link(about && about.guideUrl, 'Guide'),
    link(about && about.troubleshootingUrl, 'Troubleshooting'),
    problem,
    // A security problem (a secret that reached the AI) goes to the private
    // report form, never the public tracker (SECURITY.md).
    link(about && about.securityUrl, 'Report a security problem', said),
  ].filter(Boolean);
  shown.forEach((a, i) => links.append(...(i ? [' · ', a] : [a])));
  links.hidden = shown.length === 0;
  const security = shown.some((a) => a.textContent === 'Report a security problem');
  report.hidden = !((problem || security) && v);
  if (report.hidden) return;
  // A security report is written by hand: the line still asks for the
  // version (SECURITY.md).
  report.textContent = filled
    ? filled + (security ? ' For a security problem, say which version you run.' : '')
    : 'When you report a problem, say which version you run: Mandu ' + v + '.';
}

/** The `version` an address fills in the bug form with; null when it
 *  names none or is not an address. */
function formVersion(url) {
  try { return new URL(url).searchParams.get('version'); } catch { return null; }
}

/** About Mandu's update answer (`about.update`, dashboard.md §4.25 *A
 *  newer release*) when it is one the page can draw: `unknown`, `current`,
 *  or `newer` with its version and install command; else null (nothing to
 *  compare, and the row says nothing of updates). A `newer` answer's
 *  release notes address is kept only when it is on GitHub
 *  (`https://github.com/`), else null: an older server sends none, and
 *  the page draws no link then. */
function updateOf(about) {
  const up = about && about.update;
  if (!up || typeof up !== 'object') return null;
  if (up.state === 'unknown' || up.state === 'current') return up;
  if (up.state === 'newer' && typeof up.newest === 'string' && up.newest !== '' && typeof up.install === 'string' && up.install !== '') {
    const notes = typeof up.notesUrl === 'string' && /^https:\/\/github\.com\//.test(up.notesUrl);
    return { ...up, notesUrl: notes ? up.notesUrl : null, notesSince: notes && up.notesSince === true };
  }
  return null;
}
/** The link to what a newer release changed (§4.25 *A newer release*), in
 *  a new tab with noopener noreferrer: "What changed in Mandu <newest>",
 *  its own notes, or, when more than one release is newer than `version`
 *  (`notesSince`), "What changed since Mandu <version>", the release list.
 *  Null when the answer carries no GitHub address (updateOf). */
function releaseNotesLink(up, version) {
  if (!up || up.state !== 'newer' || !up.notesUrl) return null;
  const text = up.notesSince ? 'What changed since Mandu ' + version : 'What changed in Mandu ' + up.newest;
  return el('a', { href: up.notesUrl, target: '_blank', rel: 'noopener noreferrer', text, class: 'release-notes' });
}
/** The quiet line of About Mandu when there is no answer (§4.25 *A newer
 *  release*), by `about.update.check`: `update-check = false` in
 *  config.toml turned the check off; a source checkout with the key unset
 *  does not check; anything else (`on`, absent) checks when an agent
 *  starts. The config lines are code parts, to copy. Text and code nodes
 *  only. */
function aboutCheckParts(check) {
  if (check === 'off') return ['Mandu does not check for new releases: ', ownCode('update-check = false'), ' in config.toml. Remove that line to have it check when you start an agent.'];
  if (check === 'source') return ['This copy of Mandu runs from source, so it does not check for new releases. ', ownCode('update-check = true'), ' in config.toml turns the check on.'];
  return ['Mandu checks for a newer release when you start an agent from a terminal.'];
}
/** The Version row's update words: "This is the newest release", or "Mandu
 *  <v> is out" with the command that installs it as code (ownCode, so it
 *  can be copied), in the warn tint when it fixes security problems; then
 *  when the release list was fetched, "(checked … ago)", when known; then,
 *  for a newer release, the link to what changed (releaseNotesLink, which
 *  names the running `version` when more than one release is newer). */
function aboutUpdateNode(up, version) {
  const security = up.state === 'newer' && up.security === true;
  const span = el('span', { class: 'about-update' + (security ? ' security' : ''), 'data-update': security ? 'security' : up.state });
  if (up.state === 'current') span.append('This is the newest release');
  else span.append('Mandu ' + up.newest + (security ? ' is out with security fixes. Update now: ' : ' is out. To update: '), runCode(up.install, 'the update command'), ', then start your agent again');
  const at = whenNode(up.at);
  span.append(...(at ? [' (checked ', at, ').'] : ['.']));
  const notes = releaseNotesLink(up, version);
  if (notes) span.append(' ', notes);
  return span;
}

/** A newer Mandu fixes security problems in the version you run
 *  (dashboard.md §4.25 *A newer release*): Home's notice, shown only for
 *  such a release (a plain update stays in Settings › About Mandu), with
 *  the command, the link to what changed (releaseNotesLink) and a link to
 *  About Mandu; hidden as soon as the answer
 *  stops saying so, or a poll fails. Drawn once across polls. */
function renderUpdateNotice(home) {
  const block = document.getElementById('home-update');
  if (!block) return;
  const about = home && home.about && typeof home.about === 'object' ? home.about : null;
  const v = about && typeof about.version === 'string' && about.version !== 'unknown' ? about.version : null;
  const up = v ? updateOf(about) : null;
  const shown = up && up.state === 'newer' && up.security === true ? up : null;
  if (sameAsDrawn('update-notice', shown ? [v, shown.newest, shown.install, shown.notesUrl, shown.notesSince] : null)) return;
  block.hidden = !shown;
  if (!shown) return;
  document.getElementById('update-headline').textContent = 'A security update for Mandu is out';
  document.getElementById('update-sentence').textContent = 'Mandu ' + shown.newest + ' fixes security problems in the version you run (' + v + ').';
  const fix = document.getElementById('update-fix');
  clear(fix);
  // A modifier click is left to the browser: Settings at About Mandu, in a
  // new tab or window (its address, §4.25 *Section links*).
  const toAbout = el('a', { href: routeHref('settings') + '#about', text: 'About Mandu in Settings', onclick: (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    openAtCard('settings', 'settings-about-block');
  } });
  // What the release changed, after the command (§4.25 *A newer release*):
  // none from an older server.
  const notes = releaseNotesLink(shown, v);
  fix.append('Update now: ', runCode(shown.install, 'the update command'), ', then start your agent again. ', ...(notes ? [notes, ' · '] : []), toAbout);
}

/** The protection service refused your last edit to policy.yaml and keeps
 *  the last version that worked (dashboard.md §4.25 *An edit to policy.yaml
 *  Mandu refused*): Home's notice, from /api/home's `policyFile`, with how
 *  many problems the file has and a link to the refused line on Rules,
 *  which lists them (Home never carries their words). Hidden once an answer
 *  reads the file as valid, or names no file; a failed poll says nothing
 *  about the file, so the card stays as drawn (not called then). Drawn
 *  once across polls. */
function renderPolicyRefusedNotice(home) {
  const block = document.getElementById('home-policy-refused');
  if (!block) return;
  const f = home && home.policyFile && typeof home.policyFile === 'object' ? home.policyFile : null;
  const path = refusedPolicyPath(home);
  const shown = path !== null;
  const count = shown && Number.isInteger(f.problemCount) && f.problemCount > 0 ? f.problemCount : 0;
  const at = shown && Number.isFinite(f.refusedAt) ? f.refusedAt : null;
  if (sameAsDrawn('policy-refused', shown ? [path, count, at] : null)) return;
  block.hidden = !shown;
  if (!shown) return;
  document.getElementById('policy-refused-headline').textContent = 'Mandu did not take your last edit to policy.yaml';
  const sentence = document.getElementById('policy-refused-sentence');
  clear(sentence);
  sentence.append(nameCode(shortPath(path)), ' has a mistake, so Mandu is still using the last version that worked',
    ...(at === null ? [] : [' (since ', momentNode(new Date(at).toISOString()), ')']),
    '.', ...(count ? [' The file has ' + n(count, 'problem', 'problems') + '.'] : []));
  const fix = document.getElementById('policy-refused-fix');
  clear(fix);
  // A modifier click is left to the browser: Rules, whose refused line is
  // at its top, in a new tab or window.
  const toRules = el('a', { href: routeHref('rules'), text: 'See what is wrong in Rules', onclick: (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    openAtCard('rules', 'rules-refused', null, (line) => line);
  } });
  fix.append(toRules, ', then save the file again.');
}

/** The places whose records hold the real values behind masks: the symbol
 *  database and the session history. One of them open to others makes
 *  the headline say so. */
const REAL_VALUE_PLACES = ['symbol-db', 'events'];
/** How many places the card names by what they hold before "and N more". */
const OPEN_PLACES_NAMED = 3;
/** Other people on this computer can open places in the Mandu folder
 *  (dashboard.md §4.25q *Home warns about open places*): the notice on
 *  Home, from the `openPlaces` of /api/home (the rule of the note inside Where your
 *  data lives), naming the places by what they hold, never a path, with
 *  `mandu paths` to copy and a link that opens Where your data lives.
 *  Hidden once an answer lists none; a failed poll leaves it as drawn (not
 *  called then). The dashboard changes no mode. Drawn once across polls. */
function renderOpenPlacesNotice(home) {
  const block = document.getElementById('home-open-places');
  if (!block) return;
  const raw = home && Array.isArray(home.openPlaces) ? home.openPlaces : [];
  const places = raw.filter((p) => p && typeof p.name === 'string' && typeof p.holds === 'string' && p.holds);
  if (sameAsDrawn('open-places', places.length ? places.map((p) => [p.name, p.holds]) : null)) return;
  block.hidden = places.length === 0;
  if (!places.length) return;
  const real = places.some((p) => REAL_VALUE_PLACES.includes(p.name));
  document.getElementById('open-places-headline').textContent = real
    ? 'Other people on this computer can read the real values of your secrets'
    : 'Other people on this computer can open ' + n(places.length, 'place', 'places') + ' in Mandu\'s folder';
  const list = document.getElementById('open-places-list');
  clear(list);
  // The records of real values first: they are why the card speaks.
  const ordered = [...places.filter((p) => REAL_VALUE_PLACES.includes(p.name)), ...places.filter((p) => !REAL_VALUE_PLACES.includes(p.name))];
  for (const p of ordered.slice(0, OPEN_PLACES_NAMED)) list.append(el('li', { text: p.holds.charAt(0).toUpperCase() + p.holds.slice(1) }));
  if (ordered.length > OPEN_PLACES_NAMED) list.append(el('li', { text: 'and ' + (ordered.length - OPEN_PLACES_NAMED) + ' more' }));
  const fix = document.getElementById('open-places-fix');
  clear(fix);
  // A modifier click is left to the browser: Home at the section.
  const toData = el('a', { href: routeHref('home') + '#home-data', text: 'See every place', onclick: (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey) return;
    e.preventDefault();
    openDataLocations();
  } });
  fix.append('Run ', runCode('mandu paths'), ' in a terminal for the command that makes them yours only. ', toData);
}

/** Opens Where your data lives (reading it, as opening it by hand does)
 *  and moves the focus to its summary, in view. */
function openDataLocations() {
  const fold = document.getElementById('home-data');
  if (!fold) return;
  if (fold.open) loadDataLocations();
  else fold.open = true;
  const summary = fold.querySelector('summary');
  summary.focus({ preventScroll: true });
  if (summary.scrollIntoView) summary.scrollIntoView({ block: 'nearest' });
}

/** The policy.yaml an answer says Mandu refused (`policyFile.valid` false
 *  for a named file), else null: Home's notice and the top bar's Rules mark
 *  (renderRulesMark) follow this one condition. */
function refusedPolicyPath(home) {
  const f = home && home.policyFile && typeof home.policyFile === 'object' ? home.policyFile : null;
  return f && typeof f.path === 'string' && f.path && f.valid === false ? f.path : null;
}

/** The dashboard account (dashboard.md §6.z), from /api/home's `signIn`:
 *  Settings' Sign out for a browser signed in on the sign-in page, and the
 *  Home notice when the account file changed while the dashboard ran. A
 *  poll without an answer leaves both as they were drawn. */
function renderSignIn(home) {
  if (!home) return;
  const signIn = home.signIn && typeof home.signIn === 'object' ? home.signIn : null;
  const account = document.getElementById('settings-account-block');
  if (account) account.hidden = !(signIn && signIn.signOut === true);
  // Its section link follows it, the row changed in place.
  followSectionLinks();
  const changed = document.getElementById('home-account-changed');
  const at = signIn && typeof signIn.accountChangedAt === 'string' ? new Date(signIn.accountChangedAt) : null;
  const when = at && !Number.isNaN(at.getTime()) ? at : null;
  if (changed) changed.hidden = !when;
  const sentence = document.getElementById('account-changed-sentence');
  if (when && sentence) {
    sentence.textContent = 'The dashboard account file changed at ' + when.toLocaleString() + ', so every browser was signed out then.';
  }
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
  if (sameAsDrawn('hero', home ? [home.verdict, home.headline, home.sentence, home.sentenceParts, home.window, home.ruleChangesWaiting, home.protection && home.protection.level, home.lastSteppedIn || null] : ['failed', failure])) return;
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
  // A count is a link to what it counts (§4.25 *The counts link where they
  // point*): `to` the one session holding it, with the kind its page goes
  // to (`go`); else History's sessions where Mandu stepped in; or a page
  // (`page`). Its words stay its name ("1 action blocked"); `title` says
  // what it is and where it goes. Without `to`, plain words.
  const fact = (k, label, warn, to, title) => {
    const words = [el('strong', { class: warn ? 'warn' : '', text: String(k) }), ' ' + label];
    return to ? el('span', {}, countLink(to, title, words)) : el('span', { title: title || null }, ...words);
  };
  const where = (kind, go) => ({ session: countOwner(w, kind), go });
  if (home.verdict !== 'unknown' && home.verdict !== 'off') {
    // The same counts and words as each session's page tiles (dashboard.md
    // §4.25): secrets as its Your secrets cards tell them, never the masked
    // tokens (one file masked twice is one secret, and a secret the AI read
    // before it was marked was not masked before the AI saw it). The first
    // masked count carries the "?" of What masked means; every other count
    // its own, with what it means (COUNT_MEANINGS; never hover-only).
    // A question waiting is about now, of any age, not the window's: it comes
    // first, before the window's lead (§4.25, *The counts name their window*).
    // Said once: the waiting verdict's headline already counts them ("2
    // questions are waiting for you."), so only a headline that does not
    // (Protection failed.) gets the fact. It counts the rule changes too,
    // as the Approvals badge does.
    const waitingNow = w.waiting + (home.ruleChangesWaiting || 0);
    if (waitingNow > 0 && home.verdict !== 'waiting') facts.append(fact(waitingNow, 'waiting for you', true, { page: 'approvals' }));
    const counts = []; // the window's counts: [fact, its "?" or null]
    // A session that ran with protection off leads them, amber (§4.25 *A
    // session that ran with protection off says so*): it adds to no other
    // count, so without it the day reads as a quiet one. One session links
    // its page; several, History, whose rows mark each. An older server
    // sends no `off`: nothing.
    const off = Number.isFinite(w.off) ? w.off : 0;
    if (off > 0) {
      const owner = countOwner(w, 'off');
      counts.push([fact(off, off === 1 ? 'session ran with protection off' : 'sessions ran with protection off', true,
        owner ? { session: owner } : { page: 'history' }, COUNT_MEANINGS.off.means(off)), countHelp('off', off)]);
    }
    const masked = [];
    if (w.secretsMasked > 0) masked.push(fact(w.secretsMasked, w.secretsMasked === 1 ? 'secret masked before the AI saw it' : 'secrets masked before the AI saw them', false, where('secretsMasked', 'secrets')));
    // Masked untrusted items are the frozen levels' (integrity): plain words.
    if (w.untrusted > 0) masked.push(fact(w.untrusted, w.untrusted === 1 ? 'untrusted item masked before the AI saw it' : 'untrusted items masked before the AI saw them'));
    masked.forEach((f, i) => counts.push([f, i === 0 ? maskedHelp() : null]));
    if (w.secretsEarly > 0) {
      counts.push([fact(w.secretsEarly, w.secretsEarly === 1 ? 'secret the AI read before it was marked a secret' : 'secrets the AI read before they were marked secrets', true,
        where('secretsEarly', 'secrets'), COUNT_MEANINGS.early.means(w.secretsEarly)), countHelp('early', w.secretsEarly)]);
    }
    if (w.blocked > 0) counts.push([fact(w.blocked, w.blocked === 1 ? 'action blocked' : 'actions blocked', false, where('blocked', 'blocked')), countHelp('blocked', w.blocked)]);
    if (w.sent > 0) {
      counts.push([fact(w.sent, w.sent === 1 ? 'send with a real value filled in' : 'sends with a real value filled in', false,
        where('sent', 'sent'), COUNT_MEANINGS.sent.means(w.sent)), countHelp('sent', w.sent)]);
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
    if (facts.childElementCount === 0) {
      const empty = nothingCounted(w, span, scope);
      const last = span && !partlyCounted(w) && home.verdict !== 'failed' ? lastSteppedInWords(home.lastSteppedIn) : null;
      facts.append(last ? el('span', { class: 'dim' }, empty + ' ', ...last) : el('span', { class: 'dim', text: empty }));
    }
  }
}

/** The empty window's line goes on (dashboard.md §4.25 *An empty window
 *  says when Mandu last stepped in*): "Mandu last stepped in Fri, Oct 23,
 *  17:40, in Claude Code in ~/shop", a link to that session's page, then
 *  what Mandu did there as plain words after a colon (stepWords: ": 1
 *  secret masked, 1 action blocked"), then "See every one in History",
 *  History with its switch on (the counts' link, countLink). The moment in
 *  this browser's clock, the full date on hover. null when the server
 *  names no session (none found, an older server), and the line stays as
 *  it was. */
function lastSteppedInWords(last) {
  if (!last || typeof last !== 'object' || typeof last.id !== 'string' || last.id === '' || typeof last.agent !== 'string') return null;
  const ms = Date.parse(last.at);
  if (!Number.isFinite(ms)) return null;
  const day = WEEKDAYS[new Date(ms).getDay()].slice(0, 3);
  const words = ['Mandu last stepped in ', el('time', { class: 'moment', datetime: new Date(ms).toISOString(), title: fullClockWords(ms), text: day + ', ' + clockWords(ms) }), ', in ' + last.agent];
  if (typeof last.cwd === 'string' && last.cwd) words.push(' in ', el('code', { text: shortPath(last.cwd) }));
  const did = stepWords(last.counts);
  return [countLink({ session: last.id }, null, words), did ? ': ' + did + '. ' : '. ', countLink({}, 'Every session where Mandu stepped in.', ['See every one in History']), '.'];
}
/** What Mandu did in the session the empty window names, in the words of
 *  its History row (historyRow): rowMarks, then rowCounts, then the
 *  questions it raised that still wait, joined with commas. Read from the
 *  numbers alone: a count that is not a number is none, and protection
 *  failed only when the server says so (holds false). null with no counts
 *  (an older server) or none to say. */
function stepWords(c) {
  if (!c || typeof c !== 'object') return null;
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : 0);
  const s = c.secrets && typeof c.secrets === 'object' ? c.secrets : {};
  const row = {
    holds: c.holds !== false, protectionOff: c.protectionOff === true, lessProtection: c.lessProtection === true,
    secrets: { masked: num(s.masked), early: num(s.early) },
    untrusted: num(c.untrusted), blocked: num(c.blocked), sent: num(c.sent),
  };
  const bits = rowMarks(row);
  bits.push(...rowCounts(row));
  const waiting = num(c.waiting);
  if (waiting) bits.push(n(waiting, 'question waiting for you', 'questions waiting for you'));
  return bits.length ? bits.join(', ') : null;
}

/** The one session holding the window's count `kind` (`window.only`), or
 *  null: none or several do, the window was only partly counted, or the
 *  server is older and does not say. */
function countOwner(w, kind) {
  const id = w.only && w.only[kind];
  return typeof id === 'string' && id !== '' && !partlyCounted(w) ? id : null;
}
/** A hero count's link (§4.25 *The counts link where they point*): a page
 *  (`to.page`), or the session holding the count, opened where its tile
 *  goes (`?go=`, the tile's press), or History with its switch on, the
 *  sessions where Mandu stepped in. `about` says what the count is; the
 *  title adds where the link goes. A modifier click is the browser's (the
 *  page's links, wireNav). */
function countLink(to, about, words) {
  const say = (where) => (about ? about + ' ' : '') + where;
  if (to.page) return el('a', { href: routeHref(to.page), 'data-page-link': to.page, class: 'fact-link', title: say('Opens ' + PAGE_NAMES[to.page] + '.') }, ...words);
  if (to.session) {
    return el('a', { href: routeHref('agent', to.session, null, to.go), 'data-page-link': 'agent', 'data-session': to.session, 'data-land': to.go,
      class: 'fact-link', title: say('Opens the session where it happened.') }, ...words);
  }
  return el('a', { href: routeHref('history') + '?' + historyParams('', true), 'data-page-link': 'history', 'data-land': ONLY_STEPPED_IN,
    class: 'fact-link', title: say('Opens History: the sessions where Mandu stepped in.') }, ...words);
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

/** An attached OpenClaw Gateway's config no longer goes through Mandu
 *  (dashboard.md §4.25 *Home notices*): the server sends `routeLost` only
 *  while the service's route check finds it so; the card names each session
 *  and what changed, with the fix, and hides as soon as it stops coming. */
function renderRouteLost(home) {
  const block = document.getElementById('home-route-lost');
  if (!block) return;
  const r = home && home.routeLost;
  if (sameAsDrawn('route-lost', r || null)) return;
  block.hidden = !r;
  const items = document.getElementById('route-lost-items');
  clear(items);
  if (!r) return;
  document.getElementById('route-lost-headline').textContent = r.headline;
  document.getElementById('route-lost-sentence').textContent = r.sentence;
  for (const it of r.items || []) {
    const li = el('li', { 'data-session': String(it.session) }, textParts(it.parts, it.words));
    if (Number.isFinite(it.since)) li.append(' Since ', whenNode(it.since), '.');
    items.append(li);
  }
  const fix = document.getElementById('route-lost-fix');
  clear(fix);
  fix.append(textParts(r.fixParts, r.fix));
}

/** The newest launch left the agent's programs able to read your
 *  credential files (dashboard.md §4.23 *Product page*): the server sends
 *  `secretsPosture` only while that launch is `gated`; the card says so in
 *  the launcher's words, with the fix as a command, and hides as soon as it
 *  stops coming (a confined launch, or a failed load). */
function renderSecretsPosture(home) {
  const block = document.getElementById('home-posture');
  if (!block) return;
  const p = home && home.secretsPosture;
  if (sameAsDrawn('secrets-posture', p || null)) return;
  block.hidden = !p;
  if (!p) return;
  document.getElementById('posture-headline').textContent = p.headline;
  document.getElementById('posture-sentence').textContent = p.sentence;
  postureRest(document.getElementById('posture-note'), document.getElementById('posture-fix'), p);
}

/** The partial-layer line of a posture note and its fix, each hidden when absent. */
function postureRest(note, fix, p) {
  note.textContent = p.note || '';
  note.hidden = !p.note;
  clear(fix);
  if (p.fixParts) fix.append(textParts(p.fixParts, ''));
  fix.hidden = !p.fixParts;
}

/** The notice of the agent page, written out under its header: the session
 *  could not do its job, or a protection did not start in it
 *  (`noticeShown`; dashboard.md §4.21 *On the product page*), so the words
 *  do not wait behind the mark by its name, under a title that names which
 *  (`noticeTitle`; an older server sends none, and gets the broken title).
 *  None otherwise. */
function renderAgentNotice(vm) {
  const line = document.getElementById('agent-notice');
  if (!line) return;
  const show = !!(vm && vm.noticeShown && vm.notice);
  clear(line);
  line.hidden = !show;
  if (!show) return;
  const title = vm.noticeTitle || 'This session did not work as it should.';
  line.append(el('p', { class: 'posture-title', text: title }), el('p', null, textParts(vm.noticeParts, vm.notice)));
}

/** The line at the top of the agent page when the session recorded that it ran
 *  with protection off (`protectionOff`, dashboard.md §4.25b): Mandu only
 *  watched. While protection is off now too, it links Settings › Protection;
 *  once it is back on there is nothing there to do. None otherwise. */
function renderAgentOff(vm) {
  const line = document.getElementById('agent-off');
  if (!line) return;
  const show = !!(vm && vm.protectionOff === true);
  const linked = show && secretsRunning(S.home) === 'off';
  // Drawn again only when it changes, so a focused link keeps its focus
  // through the polls.
  const drawn = show ? (linked ? 'linked' : 'shown') : 'none';
  if (line.dataset.drawn === drawn) return;
  line.dataset.drawn = drawn;
  clear(line);
  line.hidden = !show;
  if (!show) return;
  const words = el('p', null, 'Protection was off in this session: Mandu only watched. Your secrets were not guarded and nothing was masked.');
  if (linked) words.append(' ', placeLink({ to: 'protection', text: 'Protection is in Settings' }), '.');
  line.append(words);
}

/** The agent page's line under its header: this session's launch was
 *  `gated` (dashboard.md §4.23 *Product page*); none otherwise. */
function renderAgentPosture(vm) {
  const line = document.getElementById('agent-posture');
  if (!line) return;
  const p = vm && vm.secretsPosture;
  clear(line);
  line.hidden = !p;
  if (!p) return;
  const note = el('p', { class: 'posture-note' });
  const fix = el('p', { class: 'posture-fix' });
  line.append(el('p', { class: 'posture-title', text: p.headline }), el('p', { text: p.sentence }), note, fix);
  postureRest(note, fix, p);
}

// ── The last `mandu scan` (dashboard.md §4.25ai) ─────────────────────────────
// The figure (§4.25ai *The figure*): the same secret twice, without Mandu (it
// leaves its file, goes through the agent, and the AI model receives the real
// value) and with it (it is wrapped in its mask where it crosses into Mandu,
// the model gets only the mask, the agent still works). Its glyphs are those
// of the engineering post "What Mandu is for" (the key, the dumpling that is
// the mask and the Mandu mark, the document, the agent's terminal, the green
// Mandu zone with its tab, the pill key → dumpling at its border), adapted:
// the theme's colors, and a plain "AI model" tile, never a provider's logo.
// Two layouts from one script: wide (from 540 px of figure) and narrow (a
// phone), the CSS picks one. The only motion is CSS (the lanes' dots flow,
// the key and the mask ride them), played once for under 5 s, then still;
// off under prefers-reduced-motion.
// Every word is set as text; the facts are the server's (figure VM).
const SVGNS = 'http://www.w3.org/2000/svg';
function sv(tag, attrs, ...kids) {
  const n = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v !== undefined && v !== null) n.setAttribute(k, String(v));
  for (const c of kids) if (c) n.append(c);
  return n;
}
function svText(x, y, text, cls, anchor) {
  const t = sv('text', { x, y, class: cls, 'text-anchor': anchor || 'middle' });
  t.textContent = text;
  return t;
}
const r1 = (v) => Math.round(v * 10) / 10;
function figKey(x, y, size, cls) {
  return sv('use', { href: '#scan-key', class: 'sf-key' + (cls ? ' ' + cls : ''), x: r1(x - size * 0.53), y: r1(y - size / 2), width: size, height: size });
}
function figMask(x, y, size, cls) {
  return sv('use', { href: '#scan-mandu', class: cls || null, x: r1(x - size / 2), y: r1(y - size * 31.5 / 64), width: size, height: size });
}
function figDoc(x, y, k) {
  return sv('g', { transform: `translate(${x} ${y}) scale(${k})` },
    sv('path', { class: 'sf-box', d: 'M-24 -32 H14 L28 -18 V28 Q28 32 24 32 H-24 Q-28 32 -28 28 V-28 Q-28 -32 -24 -32 Z' }),
    sv('path', { class: 'sf-fold', d: 'M14 -32 V-22 Q14 -18 18 -18 H28' }),
    figKey(-1, 2, 34));
}
function figAgent(x, y, k) {
  return sv('g', { transform: `translate(${x} ${y}) scale(${k})` },
    sv('rect', { class: 'sf-box sf-agent', x: -34, y: -24, width: 68, height: 48, rx: 7 }),
    sv('path', { class: 'sf-fold', d: 'M-34 -12 H34' }),
    sv('circle', { class: 'sf-led', cx: -26, cy: -18, r: 2 }), sv('circle', { class: 'sf-led', cx: -19, cy: -18, r: 2 }), sv('circle', { class: 'sf-led', cx: -12, cy: -18, r: 2 }),
    sv('path', { class: 'sf-prompt', d: 'M-22 -3 l7 5.5 l-7 5.5 M-10 9 h13' }));
}
/** The AI model: a plain tile with a chip on it (no provider's logo). */
function figModel(x, y, k) {
  return sv('g', { transform: `translate(${x} ${y}) scale(${k})` },
    sv('rect', { class: 'sf-box sf-model', x: -30, y: -28, width: 60, height: 56, rx: 12 }),
    sv('rect', { class: 'sf-chip', x: -11, y: -11, width: 22, height: 22, rx: 4 }),
    sv('path', { class: 'sf-pins', d: 'M-5 -11v-5M5 -11v-5M-5 11v5M5 11v5M-11 -5h-5M-11 5h-5M11 -5h5M11 5h5' }));
}
function figMark(x, y, ok, r) {
  return sv('g', { class: ok ? 'sf-ok' : 'sf-bad', transform: `translate(${x} ${y}) scale(${r / 11})` },
    sv('circle', { class: 'sf-mark', r: 11 }),
    sv('path', { class: 'sf-mark-m', d: ok ? 'M-5 .2 L-1.5 3.7 L5.2 -3.7' : 'M-4.2 -4.2 L4.2 4.2 M4.2 -4.2 L-4.2 4.2' }));
}
/** Mandu's border pill: the key goes in, its mask comes out. */
function figPill(x, y, w) {
  const h = w >= 70 ? 34 : 30;
  const g = w >= 70 ? 22 : 19;
  const off = w / 2 - 6 - g / 2;
  return sv('g', { class: 'sf-pill' },
    sv('rect', { x: r1(x - w / 2), y: r1(y - h / 2), width: w, height: h, rx: h / 2 }),
    figKey(x - off, y, g),
    sv('path', { class: 'sf-arw', d: `M${r1(x - 4.5)} ${y} h9 m-3.2 -3.2 l3.2 3.2 l-3.2 3.2` }),
    figMask(x + off, y, g + 6));
}
/** A dotted lane from p to q, with an arrowhead at q (across or down). */
function figLane(p, q, cls) {
  const [x1, y1] = p;
  const [x2, y2] = q;
  const down = x1 === x2;
  const chev = down ? `M${x2 - 5} ${y2 - 7} L${x2} ${y2 - 1} L${x2 + 5} ${y2 - 7}` : `M${x2 - 7} ${y2 - 5} L${x2 - 1} ${y2} L${x2 - 7} ${y2 + 5}`;
  return sv('g', { class: 'sf-lane-g ' + cls }, sv('path', { class: 'sf-lane', d: `M${x1} ${y1} L${x2} ${y2}` }), sv('path', { class: 'sf-chev', d: chev }));
}
/** A path cut to fit `max` characters: its last parts, after "…/". */
function cutPath(p, max) {
  if (!p || p.length <= max) return p || '';
  const parts = p.split('/');
  let out = parts.pop();
  while (parts.length && (parts[parts.length - 1] + '/' + out).length + 2 <= max) out = parts.pop() + '/' + out;
  return out.length + 2 <= max ? '…/' + out : '…' + out.slice(-(max - 1));
}
/** The two layouts, as points: wide (`w`, across: the file, the agent,
 *  then the internet on the right) and tall (`t`, down: this computer
 *  above, the internet below, every label beside its glyph), so no label is
 *  drawn smaller than about 13 px on a 360 px phone. */
const SF_LAYOUT = {
  w: {
    W: 640, H: 158, mach: [2, 2, 452, 154], net: [466, 2, 172, 154], machLbl: [16, 22, 'start'], netLbl: [480, 22, 'start'], ride: 'sf-ride',
    doc: [104, 86, 0.85], agent: [318, 86, 1], model: [540, 86, 1],
    key: [[134, 86], [280, 86]], keyIn: [[134, 86], [163, 86]], pill: [200, 86, 70], maskIn: [[237, 86], [280, 86]], out: [[356, 86], [504, 86]],
    ride1: [236, 86], ride2: [458, 86], zone: [200, 36, 236, 96], tab: [216, 36, 96], mark: [572, 58], got: [604, 100, 15],
    fileLbl: [104, 146, 'middle'], agentLbl: [318, 146, 'middle'], agentKind: [318, 128, 'middle'], modelLbl: [540, 146, 'middle'], modelKind: [540, 128, 'middle'],
    fileMax: 26, nameMax: 22,
  },
  t: {
    W: 320, H: 404, mach: [2, 2, 316, 264], net: [2, 280, 316, 122], machLbl: [16, 24, 'start'], netLbl: [116, 304, 'start'], ride: 'sf-ride-v',
    doc: [70, 74, 0.85], agent: [70, 198, 1], model: [70, 344, 1],
    key: [[70, 106], [70, 170]], keyIn: [[70, 106], [70, 119]], pill: [70, 138, 70], maskIn: [[70, 157], [70, 170]], out: [[70, 226], [70, 312]],
    ride1: [70, 138], ride2: [70, 270], zone: [14, 138, 292, 118], tab: [200, 138, 96], mark: [98, 318], got: [128, 356, 15],
    fileLbl: [116, 80, 'start'], agentLbl: [116, 208, 'start'], agentKind: [116, 188, 'start'], modelLbl: [156, 352, 'start'], modelKind: [156, 332, 'start'],
    fileMax: 20, nameMax: 18,
  },
};
/** One row of the figure, in one layout: `without` (red) or `with` (green). */
function scanFigScene(fig, row, lay) {
  const L = SF_LAYOUT[lay];
  const safe = row === 'with';
  const s = sv('svg', { class: 'sf-svg sf-' + lay, viewBox: `0 0 ${L.W} ${L.H}`, 'aria-hidden': 'true', focusable: 'false' });
  // The internet is red only where the real value goes there.
  s.append(sv('rect', { class: 'sf-mach', x: L.mach[0], y: L.mach[1], width: L.mach[2], height: L.mach[3], rx: 16 }),
    sv('rect', { class: safe ? 'sf-net sf-net-calm' : 'sf-net', x: L.net[0], y: L.net[1], width: L.net[2], height: L.net[3], rx: 16 }),
    svText(L.machLbl[0], L.machLbl[1], 'THIS COMPUTER', 'sf-region', L.machLbl[2]),
    svText(L.netLbl[0], L.netLbl[1], 'THE INTERNET', safe ? 'sf-region' : 'sf-region sf-region-net', L.netLbl[2]));
  if (safe) {
    const [zx, zy, zw, zh] = L.zone;
    s.append(sv('rect', { class: 'sf-zone', x: zx, y: zy, width: zw, height: zh, rx: 18 }));
  }
  // The lanes: the key's (to the agent; with Mandu, through its pill), then
  // the request's (to the model).
  if (safe) s.append(figLane(L.keyIn[0], L.keyIn[1], 'sf-lane-key'), figLane(L.maskIn[0], L.maskIn[1], 'sf-lane-mask'));
  else s.append(figLane(L.key[0], L.key[1], 'sf-lane-key'));
  s.append(figLane(L.out[0], L.out[1], safe ? 'sf-lane-mask' : 'sf-lane-real'));
  s.append(figDoc(L.doc[0], L.doc[1], L.doc[2]), figAgent(L.agent[0], L.agent[1], L.agent[2]), figModel(L.model[0], L.model[1], L.model[2]));
  if (safe) {
    const [tx, ty, tw] = L.tab;
    s.append(sv('g', { class: 'sf-tab' }, sv('rect', { x: tx, y: ty - 14, width: tw, height: 28, rx: 14 }),
      figMask(tx + 18, ty + 1, 20), svText(tx + 32, ty + 5, 'Mandu', 'sf-tab-t', 'start')));
    s.append(figPill(L.pill[0], L.pill[1], L.pill[2]));
    s.append(sv('g', { class: L.ride }, figMask(L.ride2[0], L.ride2[1], 30)));
  } else {
    s.append(sv('g', { class: L.ride }, figKey(L.ride1[0], L.ride1[1], 28)));
    s.append(sv('g', { class: L.ride }, figKey(L.ride2[0], L.ride2[1], 28)));
  }
  // What the model got: the real value (red) or its mask (green).
  const [gx, gy, gr] = L.got;
  s.append(sv('circle', { class: safe ? 'sf-got sf-got-ok' : 'sf-got sf-got-bad', cx: gx, cy: gy, r: gr }));
  s.append(safe ? figMask(gx, gy, 24) : figKey(gx, gy, 20));
  s.append(figMark(L.mark[0], L.mark[1], safe, 11));
  // The labels: the file, the agent, the model (its provider when known);
  // what each is, small, over a name (not over "your agent" or "AI model").
  const lbl = (p, text, cls) => svText(p[0], p[1], text, cls, p[2]);
  s.append(lbl(L.fileLbl, fig.file ? cutPath(fig.file, L.fileMax) : 'a file', 'sf-lbl'));
  s.append(lbl(L.agentLbl, fig.agent ? cutPath(fig.agent, L.nameMax) : 'your agent', 'sf-lbl'));
  s.append(lbl(L.modelLbl, fig.provider ? cutPath(fig.provider, L.nameMax) : 'AI model', 'sf-lbl'));
  if (fig.agent) s.append(lbl(L.agentKind, 'AGENT', 'sf-kind'));
  if (fig.provider) s.append(lbl(L.modelKind, 'AI MODEL', 'sf-kind'));
  return s;
}
/** The whole figure (the Scan page's): a heading, its two rows, each with
 *  its label, both layouts of its scene, and its steps; then the green line. */
function scanFigure(fig, safeLine) {
  const box = el('figure', { class: 'scan-fig', 'aria-labelledby': 'scan-fig-title' });
  box.append(el('h2', { id: 'scan-fig-title', class: 'scan-fig-title', text: fig.title }));
  for (const [row, part] of [['without', fig.without], ['with', fig.with]]) {
    const ok = row === 'with';
    const r = el('div', { class: 'scan-fig-row', 'data-row': row, 'data-tone': ok ? 'ok' : 'bad' });
    r.append(el('p', { class: 'scan-fig-label' }, el('span', { class: 'tone-mark' }, svg(ok ? ICON.check : ICON.x, 14)), part.label));
    r.append(el('div', { class: 'sf-scene' }, scanFigScene(fig, row, 'w'), scanFigScene(fig, row, 't')));
    const steps = el('ol', { class: 'scan-fig-steps' });
    for (const s of part.steps || []) steps.append(el('li', {}, countWords(s)));
    r.append(steps);
    box.append(r);
  }
  if (safeLine) box.append(el('p', { class: 'scan-safe' }, el('span', { class: 'tone-mark' }, svg(ICON.check, 14)), safeLine));
  return box;
}
/** The small flow: file → agent → the AI model, and what it got. One row
 *  of chips (Home's card, each of your secrets on the Scan page). */
function scanFlow(f) {
  const ok = f.reached === 'masked';
  const arrow = () => el('span', { class: 'sf-arrow', 'aria-hidden': 'true', text: '→' });
  const chip = (icon, text, cls) => el('span', { class: 'sf-chip-h' + (cls ? ' ' + cls : '') }, icon, el('span', { text }));
  const maskIcon = () => { const s = sv('svg', { viewBox: '0 0 64 64', width: 16, height: 16, 'aria-hidden': 'true' }); s.append(sv('use', { href: '#scan-mandu' })); return s; };
  const row = el('p', { class: 'scan-flow', 'data-tone': ok ? 'ok' : 'bad' });
  const chips = [];
  if (f.file) chips.push(chip(svg(ICON.file, 14), cutPath(f.file, 32)));
  if (ok) chips.push(chip(maskIcon(), 'masked by Mandu', 'sf-chip-mask'));
  chips.push(chip(svg(ICON.terminal, 14), f.agent));
  chips.push(chip(svg(ok ? ICON.check : ICON.x, 14), (f.provider ? f.provider + '’s AI' : 'the AI') + (ok ? ' got only the mask' : ' got the real value'), ok ? 'sf-chip-ok' : 'sf-chip-bad'));
  // An arrow goes with the chip it points at, so a line never ends on one.
  chips.forEach((c, i) => row.append(i === 0 ? c : el('span', { class: 'sf-next' }, arrow(), c)));
  return row;
}
/** The card on Home: how many of your secrets already left this computer in
 *  the requests of your agents (the "your secrets" of the scan, in sessions without Mandu),
 *  the top ones with their name and file, the sends worth a look, and the
 *  command; with no scan kept, how to run one. No answer, or a server that
 *  sends no `scan`: no card. */
function renderHomeScan(home) {
  const block = document.getElementById('home-scan');
  const card = home && home.scan;
  if (sameAsDrawn('home-scan', card || null)) {
    if (card) foldHomeScan(card);
    return;
  }
  block.hidden = !card;
  const top = document.getElementById('home-scan-top');
  clear(top);
  if (!card) return;
  block.dataset.ran = card.ran ? 'yes' : 'no';
  // Red when some of your secrets left, green when none did (the server's
  // tone, never read from the words), with a mark beside the words.
  block.dataset.tone = card.tone || '';
  const headline = document.getElementById('home-scan-headline');
  clear(headline);
  if (card.tone === 'bad' || card.tone === 'ok') headline.append(el('span', { class: 'tone-mark' }, svg(card.tone === 'ok' ? ICON.check : ICON.x, 16)));
  headline.append(card.headline);
  const safe = document.getElementById('home-scan-safe');
  safe.hidden = !card.safeLine;
  clear(safe);
  if (card.safeLine) safe.append(el('span', { class: 'tone-mark' }, svg(ICON.check, 14)), card.safeLine);
  // The figure, small: the two flows of the Scan page's figure as chips.
  const figBox = document.getElementById('home-scan-figure');
  clear(figBox);
  const fig = card.figure;
  figBox.hidden = !(fig && fig.leaked);
  if (fig && fig.leaked) {
    figBox.append(el('p', { class: 'scan-flow-label', 'data-tone': 'bad' }, 'Without Mandu'),
      scanFlow({ file: fig.file, agent: fig.agent, provider: fig.provider, reached: 'real' }),
      el('p', { class: 'scan-flow-label', 'data-tone': 'ok' }, 'With Mandu'),
      scanFlow({ file: fig.file, agent: fig.agent, provider: fig.provider, reached: 'masked' }));
  }
  const when = document.getElementById('home-scan-when');
  when.hidden = !card.when;
  when.textContent = card.when || '';
  const sentence = document.getElementById('home-scan-sentence');
  clear(sentence);
  sentence.append(textParts(card.parts, card.sentence));
  for (const f of card.top || []) {
    top.append(el('li', {}, el('span', { class: 'scan-top-name' }, ownCode(f.name), f.file ? ' in ' : '', f.file ? ownCode(f.file) : ''),
      el('span', { class: 'dim scan-top-how', text: f.how }), typeof f.ruleFile === 'string' && f.ruleFile ? scanRuleLink(f.ruleFile) : ''));
  }
  if (card.more > 0) top.append(el('li', { class: 'dim' }, countWords('and ' + card.more + ' more on the Scan page')));
  const worth = document.getElementById('home-scan-worth');
  worth.hidden = !card.worthWords;
  clear(worth);
  if (card.worthWords) worth.append(el('span', { class: 'tone-mark' }, svg(ICON.alert, 14)), card.worthWords);
  const sug = document.getElementById('home-scan-suggested');
  sug.hidden = !card.suggested;
  clear(sug);
  if (card.suggested) sug.append(card.suggested, ' ', placeLink({ to: 'suggested', text: 'Review them' }));
  const again = document.getElementById('home-scan-again');
  clear(again);
  again.append(textParts(card.againParts, ''));
  document.getElementById('home-scan-open').hidden = !card.link;
  // The folded line: the words of the server, the ✓ after a clean scan (never
  // before one: the question is no result), the Scan page linked as the
  // open card links it.
  const folded = document.getElementById('home-scan-folded-text');
  clear(folded);
  if (typeof card.folded === 'string') {
    const mark = card.tone === 'ok' ? el('span', { class: 'tone-mark' }, svg(ICON.check, 14)) : '';
    if (card.link) folded.append(el('a', { href: routeHref(card.link), 'data-page-link': card.link }, mark, card.folded));
    else folded.append(mark, card.folded);
  }
  foldHomeScan(card);
}
/** The card on Home folded to one line (dashboard.md §4.25ai *A card with
 *  nothing to act on folds*), in this browser: the key holds the `ranAt` of
 *  the scan it was folded on ('none' before any scan). Only a card the server
 *  sends a `folded` line for folds, and only on that scan: a new scan opens
 *  it, and a card that says secrets left, or asks something, never folds.
 *  Where storage fails it holds for this tab. */
const SCAN_FOLD_KEY = 'mandu.home.scanFolded';
const scanFoldOf = (card) => card.ranAt || 'none';
function scanFoldedOn() { return S.scanFoldTab !== undefined ? S.scanFoldTab : lsGet(SCAN_FOLD_KEY); }
function setScanFold(on) {
  try {
    if (on === null) localStorage.removeItem(SCAN_FOLD_KEY);
    else localStorage.setItem(SCAN_FOLD_KEY, on);
    S.scanFoldTab = undefined;
  } catch { S.scanFoldTab = on; }
}
function foldHomeScan(card) {
  const can = typeof card.folded === 'string';
  const folded = can && scanFoldedOn() === scanFoldOf(card);
  const block = document.getElementById('home-scan');
  block.dataset.folded = folded ? 'yes' : 'no';
  block.setAttribute('aria-labelledby', folded ? 'home-scan-folded-text' : 'home-scan-headline');
  document.getElementById('home-scan-head').hidden = folded;
  document.getElementById('home-scan-body').hidden = folded;
  document.getElementById('home-scan-folded').hidden = !folded;
  document.getElementById('home-scan-fold').hidden = !can;
}
/** Fold or Show: the focus goes on with the button, to Show once folded, to
 *  the heading of the card once open. */
function foldScanCard(fold) {
  const card = S.home && S.home.scan;
  if (!card || typeof card.folded !== 'string') return;
  setScanFold(fold ? scanFoldOf(card) : null);
  foldHomeScan(card);
  document.getElementById(fold ? 'home-scan-show' : 'home-scan-headline').focus();
}
/** The line of History on the sessions your agents ran without Mandu
 *  (dashboard.md §4.25ai): the card Home draws, in a line, its words those of
 *  the server. Before any scan, the command that reads them (with its Copy)
 *  and a link to how it works; after one, the headline of the card as the
 *  link to the Scan page and its `when`, a ✗ beside a headline that says some
 *  left. No answer, or a server that sends no `scan`: a plain link, never a
 *  claim of what a scan found. */
function renderHistoryScan(home) {
  const line = document.getElementById('history-scan');
  const card = home && home.scan;
  const run = card && Array.isArray(card.againParts) ? card.againParts.find((p) => p && p.kind === 'code') : null;
  if (sameAsDrawn('history-scan', card ? [card.ran, card.headline, card.when, card.tone, run || null] : null)) return;
  clear(line);
  line.dataset.tone = (card && card.ran && card.tone) || '';
  const scanLink = (...words) => el('a', { href: routeHref('scan'), 'data-page-link': 'scan' }, ...words);
  if (!card) line.append('Sessions your agents ran without Mandu: ', scanLink('the Scan page'), '.');
  else if (!card.ran) {
    line.append('Sessions your agents ran without Mandu are not listed here. ', run ? textParts([run], '') : ownCode('mandu scan'),
      ' reads them and shows which of your secrets already went to the AI. ', scanLink('How it works'), '.');
  } else {
    line.append('Sessions your agents ran without Mandu: ',
      scanLink(card.tone === 'bad' ? el('span', { class: 'tone-mark' }, svg(ICON.x, 14)) : null, card.headline), '.', card.when ? ' ' + card.when + '.' : '');
  }
}

/** A scan finding's file opens in Rules, to change who may get it
 *  (§4.25ai): the session card's link (§4.25b *A card opens its file in
 *  Rules*), a plain link, so a new tab, a bookmark and Back work. */
function scanRuleLink(file) {
  return el('div', { class: 'secret-rule scan-rule' },
    el('a', { href: routeHref('rules', file), 'data-page-link': 'rules', 'data-file': file, class: 'secret-rule-link',
      text: 'Change it in Rules', 'aria-label': 'Change the rule for ' + file + ' in Rules' }));
}

/** One line of where a company replaces a key (dashboard.md §4.25r, the
 *  Scan page too, §4.25ai): the lead, the page as a link in a new tab with
 *  no referrer (a dashboard address can name a file), the words after. */
function replaceLine(r, cls) {
  return el('p', { class: 'detail-note ' + cls }, r.lead + ': ',
    el('a', { href: r.url, target: '_blank', rel: 'noopener noreferrer', text: r.page }), r.after || '');
}

/** The rows a section shows at once; Show more adds as many again (the
 *  head's `pageRows`, the server's SCAN_PAGE_ROWS, when it says). */
const SCAN_PAGE_ROWS = 25;
/** The Scan page's read (§4.25ai *A long scan, in pages*): the head's `rev`
 *  (which kept scan its rows are of; a page asked of another is refused
 *  409 and the page reads again), its rows a page, whether the last
 *  read failed (`unread`: read again once a Home poll answers) and the
 *  visit it was last drawn in (`drawn`: before that, the page shown is the
 *  last visit's, whose place is not this one's; scanPlace), the visit
 *  whose Back is landing with scroll anchoring off (`landing`,
 *  scanLandPlace), and the head drawn (`vm`: its start commands follow the
 *  `start` of Home). */
const SC = { rev: null, pageRows: SCAN_PAGE_ROWS, unread: false, reading: false, followed: undefined, drawn: 0, landing: 0, vm: null };
/** How long the filter waits after a key before it asks the server. */
const SCAN_FIND_WAIT_MS = 150;
/** Each drawn section's box → its Show more read (`more`), how many rows it
 *  has drawn (`drawn`), whether it has no more pages (`ended`) or its last
 *  read failed (`failed`, `failure`), and whether *Find one* has text (`found`); each row
 *  fold → the read of its examples. The place of the page reads them
 *  (scanPlace) and Back puts it back with them (scanLandPlace). */
const SCAN_SECTION = new WeakMap();
const SCAN_FOLD_READ = new WeakMap();

/** Does Home's scan card name another kept scan than the page drew
 *  (§4.25ai *The Scan page follows a new scan*)? Its `rev` is the one
 *  GET /api/scan sends (null: none kept); a card without one (an older
 *  server) never does, and a `rev` already followed is not read twice. */
function scanFollows(card) {
  if (!card || !('rev' in card) || (card.rev !== null && typeof card.rev !== 'string')) return false;
  if (SC.reading || SC.unread || card.rev === SC.rev || card.rev === SC.followed) return false;
  SC.followed = card.rev;
  return true;
}

/** The read of the Scan page: GET /api/scan (its head), drawn once it
 *  answers. A failed read says why and is read again on the next poll
 *  that answers (loadHome). `follow`: a poll's read of a scan kept since
 *  (scanFollows): the same scan draws nothing again (an open fold, *Find
 *  one* and the place stay); another is drawn where you were, and a status
 *  line says so once. */
async function loadScan(follow) {
  const visit = S.visit;
  let vm = null;
  let failure = null;
  const followed = document.getElementById('scan-followed') || { hidden: true, textContent: '' };
  // A link's row it could not open (scanItemMissing): said of the scan drawn.
  const missing = document.getElementById('scan-item-missing') || { hidden: true, textContent: '' };
  SC.reading = true;
  if (!follow) { SC.followed = undefined; followed.hidden = true; followed.textContent = ''; missing.hidden = true; missing.textContent = ''; }
  try { vm = (await apiGet('scan')).scan || null; } catch (err) { failure = readFailure(err); }
  SC.reading = false;
  if (S.visit !== visit || S.page !== 'scan') return;
  // A follow that could not read keeps the page drawn, and the next poll
  // tries again; one that finds the same scan draws nothing.
  if (follow && !vm) { SC.followed = undefined; return; }
  const rev = (vm && typeof vm.rev === 'string' && vm.rev) || null;
  if (follow && rev === SC.rev) return;
  missing.hidden = true;
  missing.textContent = '';
  if (follow && vm.ran) { followed.textContent = 'A new scan finished. This page shows it.'; followed.hidden = false; }
  else if (follow) { followed.hidden = true; followed.textContent = ''; }
  SC.unread = !vm;
  SC.rev = rev;
  SC.pageRows = (vm && Number.isInteger(vm.pageRows) && vm.pageRows > 0) ? vm.pageRows : SCAN_PAGE_ROWS;
  const y = window.scrollY;
  renderScanPage(vm, failure);
  SC.drawn = S.visit;
  // Drawn where you were, never back at the top (a shorter page meanwhile
  // may have held it above).
  if (follow && window.scrollY !== y) window.scrollTo(0, y);
}

/** A part of the Scan page read when opened (a section's next rows or its
 *  filter's matches, a row's examples): { data } or { failure }. An answer
 *  that says the scan changed reads the page again. */
async function scanPart(path) {
  const rev = SC.rev;
  const q = rev ? (path.includes('?') ? '&' : '?') + 'rev=' + encodeURIComponent(rev) : '';
  try { return { data: await apiGet(path + q) }; } catch (err) {
    if (err && err.status === 409 && S.page === 'scan' && rev === SC.rev) loadScan();
    return { failure: readFailure(err) };
  }
}

/** The panel of examples of one finding: the date range, the projects, then
 *  each example (when, the agent, the project, the command or the file, and
 *  with or without Mandu, small). `item` is GET scan/item/<id>'s answer. */
function scanDetail(item) {
  const d = item.detail || {};
  const box = el('div', { class: 'scan-detail' });
  if (d.where && Array.isArray(d.where.rows) && d.where.rows.length) box.append(scanWhereNow(d.where));
  const facts = [d.range ? 'When: ' + d.range : null, d.projects ? 'In ' + d.projects : null].filter(Boolean);
  if (facts.length) box.append(el('p', { class: 'note' }, countWords(facts.join(' · '))));
  const groups = (d.groups || []).filter((g) => g.examples && g.examples.length);
  for (const g of groups) {
    box.append(el('p', { class: 'scan-group-title', text: g.title }));
    const list = el('ol', { class: 'scan-examples' });
    for (const e of g.examples) {
      list.append(el('li', {},
        el('span', { class: 'scan-example-head', text: e.head }),
        el('span', { text: e.did }), e.code ? ' ' : '', e.code ? ownCode(e.code) : '',
        e.mandu ? el('span', { class: 'dim scan-example-mandu', text: ' (' + e.mandu + ')' }) : ''));
    }
    box.append(list);
  }
  if (!groups.length) {
    box.append(el('p', { class: 'note dim', text: 'This scan kept no examples of it. Run mandu scan again for them.' }));
  }
  return box;
}

/** *Where the real value is now* (§4.25ai): one row a place (where it
 *  belongs, the AI service that got it, each chat-history file it sits
 *  in), each with how it got there, when, and what it is now in its tone;
 *  a chat history under Mandu links its sessions. Then what to do. */
function scanWhereNow(w) {
  const box = el('div', { class: 'scan-where', role: 'group', 'aria-label': 'Where the real value is now' });
  box.append(el('p', { class: 'scan-group-title scan-where-title', text: 'Where the real value is now' }));
  const list = el('ul', { class: 'scan-where-rows' });
  for (const r of w.rows) {
    const icon = TONE_ICON[r.tone];
    const links = (r.sessions || []).filter((s) => typeof s === 'string' && s).map((s, i) =>
      el('a', { href: routeHref('agent', s), 'data-page-link': 'agent', 'data-session': s, class: 'scan-where-session', text: (r.sessions.length > 1 ? 'Session ' + (i + 1) : 'Open the session') }));
    list.append(el('li', { class: 'scan-where-row', 'data-kind': r.kind, 'data-tone': r.tone || 'plain' },
      el('div', { class: 'scan-where-place' },
        el('span', { class: 'scan-where-name', text: r.where }),
        r.file ? ownCode(r.file) : ''),
      el('div', { class: 'scan-where-how' }, r.how, r.first ? el('span', { class: 'dim', text: ' · since ' + r.first }) : ''),
      el('div', { class: 'scan-where-now' }, icon ? el('span', { class: 'tone-mark' }, svg(ICON[icon], 12)) : null, r.now,
        ...links.flatMap((a) => [' · ', a]))));
  }
  box.append(list);
  if (w.more) box.append(el('p', { class: 'note dim', text: w.more }));
  if (w.advice) box.append(el('p', { class: 'note scan-where-advice', text: w.advice }));
  return box;
}

/** One finding: its title and summary, the story of how it left this
 *  computer, the footnote on Mandu, and a fold with its examples. */
const TONE_ICON = { bad: 'x', ok: 'check', warn: 'alert' };
function scanItem(item) {
  const row = el('li', { class: 'scan-item', 'data-id': item.id, 'data-tone': item.tone || 'plain' });
  const icon = TONE_ICON[item.tone];
  const badge = item.badge ? el('span', { class: 'scan-badge' }, icon ? svg(ICON[icon], 12) : null, item.badge) : null;
  row.append(el('div', { class: 'scan-item-head' }, el('div', { class: 'scan-item-title' }, ownCode(item.title)), badge));
  row.append(el('div', { class: 'dim scan-item-summary', text: item.summary }));
  if (item.flow) row.append(scanFlow(item.flow));
  const story = el('ul', { class: 'scan-story' });
  for (const s of item.story || []) {
    const mark = s.tone === 'ok' || s.tone === 'bad' ? el('span', { class: 'tone-mark' }, svg(ICON[TONE_ICON[s.tone]], 13)) : null;
    story.append(el('li', { class: 'scan-step', 'data-step': s.step, 'data-tone': s.tone || 'plain' }, mark, textParts(s.parts, s.text)));
  }
  row.append(story);
  // A key not in your files, or sent on: where its company replaces it,
  // in case it is still yours (§4.25ai).
  for (const r of item.replaceAt || []) row.append(replaceLine(r, 'scan-replace'));
  if (typeof item.file === 'string' && item.file) row.append(scanRuleLink(item.file));
  if (item.footnoteParts && item.footnoteParts.length) {
    row.append(el('p', { class: 'note scan-footnote' }, ...item.footnoteParts.map((p) => el('span', { 'data-tone': p.tone, text: p.text }))));
  } else if (item.footnote) row.append(el('p', { class: 'note dim scan-footnote', text: item.footnote }));
  // Its examples are read when the fold first opens (GET scan/item/<id>);
  // a failed read says why, and the next opening tries again.
  // The read is held by the fold (SCAN_FOLD_READ), so Back can await it
  // (scanLandPlace); one already out is the one returned.
  const fold = el('details', { class: 'scan-more' }, el('summary', { text: 'Details and examples' }));
  let reading = Promise.resolve();
  const read = () => {
    if (!fold.open || fold.dataset.read === 'yes') return Promise.resolve();
    if (fold.dataset.read === 'reading') return reading;
    fold.dataset.read = 'reading';
    reading = (async () => {
      while (fold.childElementCount > 1) fold.lastElementChild.remove();
      const wait = el('p', { class: 'note dim scan-reading', text: 'Reading…' });
      fold.append(wait);
      const r = await scanPart('scan/item/' + encodeURIComponent(item.id));
      wait.remove();
      if (r.data && r.data.detail) {
        fold.dataset.read = 'yes';
        fold.append(scanDetail(r.data));
      } else {
        fold.dataset.read = '';
        fold.append(el('p', { class: 'note scan-unread' }, ...cannotCheck('The examples could not be read.', r.failure || null, true)));
      }
    })();
    return reading;
  };
  fold.addEventListener('toggle', read);
  SCAN_FOLD_READ.set(fold, read);
  row.append(fold);
  return row;
}

/** What *Find one* counts in each section (its rows are values), by section id. */
const SCAN_FIND_NOUN = { looks: ['value', 'values'], named: ['value', 'values'], kept: ['value', 'values'] };
/** The longest query a *Find one* count echoes, in characters. */
const SCAN_FIND_ECHO = 60;
/** One section: its heading, sentence, filter (a long tier) and rows. The
 *  head carries its first rows and its count (`total`, `next`); Show more
 *  reads the next page of the section, and *Find one* asks the server for
 *  the section's rows that match (over the whole section, not the rows
 *  drawn). Folded when the tier is long. */
function scanSection(sec) {
  const box = el('section', { class: 'block scan-section', 'data-section': sec.id, 'data-tone': sec.tone || 'plain', 'aria-label': sec.heading });
  const list = el('ul', { class: 'scan-items' });
  const moreBtn = el('button', { type: 'button', class: 'btn small', hidden: true });
  const unread = el('p', { class: 'note scan-unread', hidden: true });
  const pageRows = SC.pageRows;
  const head = { rows: (sec.items || []).slice(), total: Number.isInteger(sec.total) ? sec.total : (sec.items || []).length, next: Number.isInteger(sec.next) ? sec.next : null };
  // What is drawn: the rows, how many match in all, the next page's start,
  // the query they answer; `asked` counts the reads, so an older answer
  // (a key typed meanwhile) never draws over a newer one.
  const st = { rows: head.rows.slice(), total: head.total, next: head.next, query: '', said: '', asked: 0, busy: false, failed: false, failure: null };
  // The status line of *Find one* (§4.25ai): how many rows of the section the
  // query matches, or that none does (findCount: heard, the list shows
  // "None matches."); no query or a failed read: hidden. Written only when
  // its words change, so Show more says nothing again.
  const counter = sec.filter ? el('p', { class: 'history-count', id: 'scan-find-count-' + sec.id, role: 'status', hidden: true }) : null;
  const drawCount = (failed) => {
    if (!counter) return;
    const [one, many] = SCAN_FIND_NOUN[sec.id] || ['row', 'rows'];
    const chars = Array.from(st.said);
    const q = '\u201c' + (chars.length > SCAN_FIND_ECHO ? chars.slice(0, SCAN_FIND_ECHO).join('') + '\u2026' : st.said) + '\u201d';
    const all = head.total.toLocaleString('en-US');
    const on = !!st.query && !failed;
    findCount(counter, on && st.total > 0 ? st.total.toLocaleString('en-US') + ' of ' + all + ' ' + (head.total === 1 ? one : many) + (st.total === 1 ? ' matches ' : ' match ') + q + '.' : '',
      on && st.total <= 0 ? 'No ' + one + ' of ' + all + ' matches ' + q + '.' : '');
  };
  const say = (lead, failure) => {
    clear(unread);
    unread.hidden = !lead;
    if (lead) unread.append(...cannotCheck(lead, failure, true));
  };
  const drawMore = () => {
    const left = st.total - st.rows.length;
    moreBtn.hidden = st.next === null || left <= 0;
    moreBtn.disabled = st.busy;
    moreBtn.textContent = 'Show ' + Math.min(pageRows, Math.max(left, 0)) + ' more';
  };
  const draw = () => {
    clear(list);
    for (const i of st.rows) list.append(scanItem(i));
    if (!st.rows.length && unread.hidden) list.append(el('li', { class: 'empty', 'data-tone': !st.query && sec.emptyTone ? sec.emptyTone : null, text: st.query ? 'None matches.' : sec.empty || 'None.' }));
    drawMore();
  };
  const sectionPath = (after, query) => 'scan/section/' + encodeURIComponent(sec.id) + '?after=' + after + (query ? '&q=' + encodeURIComponent(query) : '');
  // Show more: the next page of the section. True when it drew rows (Back
  // reads on with it, a page at a time: scanLandPlace).
  const more = async () => {
    if (st.busy || st.next === null) return false;
    st.busy = true;
    drawMore();
    const asked = st.asked;
    const r = await scanPart(sectionPath(st.next, st.query));
    st.busy = false;
    if (asked !== st.asked) { drawMore(); return false; }
    const read = !!(r.data && Array.isArray(r.data.items));
    // How the last read went, for a link reading on (scanReadTo).
    st.failed = !read;
    st.failure = read ? null : r.failure || null;
    if (read) {
      say(null);
      for (const i of r.data.items) { st.rows.push(i); list.append(scanItem(i)); }
      st.total = r.data.total;
      st.next = r.data.next;
      drawCount(false);
    } else say('The next rows could not be read.', r.failure || null);
    drawMore();
    // Rows added without a scroll: the place is saved (savePlace).
    if (read && S.page === 'scan') savePlace();
    return read && r.data.items.length > 0;
  };
  moreBtn.addEventListener('click', more);
  const find = async (value) => {
    const query = value.trim().toLowerCase();
    const asked = ++st.asked;
    st.busy = false;
    if (!query) {
      Object.assign(st, { rows: head.rows.slice(), total: head.total, next: head.next, query: '', said: '' });
      say(null);
      drawCount(false);
      return draw();
    }
    const r = await scanPart(sectionPath(0, query));
    if (asked !== st.asked) return;
    Object.assign(st, { query, said: value.trim() });
    const read = !!(r.data && Array.isArray(r.data.items));
    if (read) {
      say(null);
      Object.assign(st, { rows: r.data.items, total: r.data.total, next: r.data.next });
    } else {
      Object.assign(st, { rows: [], total: 0, next: null });
      say('The matching rows could not be read.', r.failure || null);
    }
    drawCount(!read);
    draw();
  };
  const body = el('div', { class: 'scan-section-body' }, el('p', { class: 'note', text: sec.sentence }));
  if (sec.filter) {
    const id = 'scan-filter-' + sec.id;
    const input = el('input', { type: 'search', id, class: 'scan-filter', placeholder: 'A mask, a project, a command', autocomplete: 'off', spellcheck: 'false', maxlength: '200', 'aria-describedby': counter.id });
    let timer = 0;
    input.addEventListener('input', () => {
      clearTimeout(timer);
      timer = setTimeout(() => find(input.value), SCAN_FIND_WAIT_MS);
      // Find is never kept: with text in it the place is the top (savePlace).
      savePlace();
    });
    body.append(el('div', { class: 'scan-filter-row' }, el('label', { for: id, text: 'Find one' }), input, counter));
  }
  body.append(list, unread, moreBtn);
  draw();
  // The heading's mark says its tone in a shape too (✗ red, ! amber, ✓ green).
  const icon = TONE_ICON[sec.tone];
  const mark = () => (icon ? el('span', { class: 'tone-mark' }, svg(ICON[icon], 15)) : null);
  if (sec.folded) {
    box.append(el('details', { class: 'scan-fold' }, el('summary', {}, el('h2', { class: 'scan-fold-title' }, mark(), sec.heading)), body));
  } else {
    box.append(el('h2', {}, mark(), sec.heading), body);
  }
  // What the place of the page reads (scanPlace) and Back reads on with;
  // a link reads on with it too (scanReadTo), told whether the section has
  // no more pages (`ended`) or its last read failed (`failed`, `failure`).
  SCAN_SECTION.set(box, { more, drawn: () => st.rows.length, ended: () => st.next === null, failed: () => st.failed, failure: () => st.failure, found: () => !!st.query || (!!sec.filter && body.querySelector('input.scan-filter').value.trim() !== '') });
  return box;
}

/** The Scan page from its answer; no answer: it says it could not read it. */
function renderScanPage(vm, failure) {
  const sentence = document.getElementById('scan-sentence');
  const read = document.getElementById('scan-read');
  const notes = document.getElementById('scan-notes');
  const sections = document.getElementById('scan-sections');
  const riskBlock = document.getElementById('scan-risk-block');
  const risk = document.getElementById('scan-risk');
  const figure = document.getElementById('scan-figure');
  const end = document.getElementById('scan-end');
  clear(sentence); clear(notes); clear(sections); clear(risk); clear(figure);
  if (!vm) {
    // Only what is true: the plain headline, uncoloured, and why it could
    // not be read. Nothing of an earlier read stays under it, drawn or in
    // the text (§4.25ai *A Scan page that cannot be read says only that*).
    SC.vm = null;
    document.getElementById('scan-headline').textContent = 'What your agents already sent to the AI';
    delete document.getElementById('page-scan').dataset.tone;
    sentence.append(...cannotCheck('The last scan could not be read.', failure, true));
    read.hidden = true; notes.hidden = true; riskBlock.hidden = true; figure.hidden = true; sections.hidden = true;
    read.textContent = '';
    scanStep(null);
    for (const id of ['scan-suggested', 'scan-stop', 'scan-again']) clear(document.getElementById(id));
    end.hidden = true;
    return;
  }
  end.hidden = false;
  const headline = document.getElementById('scan-headline');
  clear(headline);
  if (vm.tone === 'bad' || vm.tone === 'ok') headline.append(el('span', { class: 'tone-mark' }, svg(vm.tone === 'ok' ? ICON.check : ICON.x, 22)));
  headline.append(vm.headline);
  document.getElementById('page-scan').dataset.tone = vm.tone || '';
  SC.vm = vm;
  drawScanStart(vm);
  figure.hidden = !vm.figure;
  if (vm.figure) figure.append(scanFigure(vm.figure, vm.safeLine));
  read.hidden = !vm.read;
  read.textContent = vm.read || '';
  notes.hidden = !(vm.notes && vm.notes.length);
  for (const n of vm.notes || []) notes.append(el('li', {}, countWords(n)));
  for (const sec of vm.sections || []) sections.append(scanSection(sec));
  // No section (no scan yet): no room either, so the step sits one block
  // gap under the sentence (§4.25ai *Before any scan, the step comes first*).
  sections.hidden = !sections.firstChild;
  riskBlock.hidden = !(vm.risk && vm.risk.length);
  // Worth a look: amber, with its mark (drawn once).
  riskBlock.dataset.tone = 'warn';
  const riskTitle = document.getElementById('scan-risk-title');
  if (!riskTitle.querySelector('.tone-mark')) riskTitle.prepend(el('span', { class: 'tone-mark' }, svg(ICON.alert, 15)));
  for (const r of vm.risk || []) risk.append(el('li', {}, countWords(r)));
  const sug = document.getElementById('scan-suggested');
  sug.hidden = !vm.suggested;
  clear(sug);
  if (vm.suggested) sug.append(vm.suggested, ' ', placeLink({ to: 'suggested', text: 'Review them' }));
  const again = document.getElementById('scan-again');
  clear(again);
  // Before any scan the way to run one is the step of the page, drawn first;
  // after one, Run it again closes the page.
  const first = !vm.ran && typeof vm.stepNote === 'string' && vm.stepNote !== '';
  again.hidden = first;
  if (first) scanStep(vm);
  else { scanStep(null); again.append(textParts(vm.againParts, '')); }
}

/** The two sentences of the Scan page that name the commands that start
 *  your agent, its summary and its stop line, from the `start` of Home
 *  (§4.25ai *The Scan page names the agent you use*); drawn again by a Home
 *  poll only when that list changed (sameAsDrawn), and nothing else on the
 *  page. */
function drawScanStart(vm) {
  const list = homeStart(S.home);
  sameAsDrawn('scan-start', list);
  const sentence = document.getElementById('scan-sentence');
  clear(sentence);
  sentence.append(textParts(withStart(vm.parts, list), vm.sentence));
  const stop = document.getElementById('scan-stop');
  clear(stop);
  stop.append(textParts(withStart(vm.stopParts, list), ''));
}

/** The step of a Scan page before any scan (its `againParts`, at body size)
 *  and the line under it; null hides both (a scan kept, or a failed read). */
function scanStep(vm) {
  const step = document.getElementById('scan-step');
  const note = document.getElementById('scan-step-note');
  if (!step || !note) return;
  clear(step);
  note.textContent = vm ? vm.stepNote : '';
  if (vm) step.append(textParts(vm.againParts, ''));
  step.hidden = !vm;
  note.hidden = !vm;
}

/** The read of the Plugins page (dashboard.md §4.25aj): `reading` while one is
 *  out, so a poll does not ask twice. */
const PL = { reading: false };

/** The read of the Plugins page: GET /api/plugins, drawn once it answers;
 *  each Home poll reads it again while the page is shown (loadHome). */
async function loadPlugins() {
  const visit = S.visit;
  let vm = null;
  let failure = null;
  PL.reading = true;
  try { vm = (await apiGet('plugins')).plugins || null; } catch (err) { failure = readFailure(err); }
  PL.reading = false;
  if (S.visit !== visit || S.page !== 'plugins') return;
  renderPluginsPage(vm, failure);
}

/** The mark of a tone beside its words (never the color alone, §4.25ai *Color
 *  with meaning*). */
const PLUGIN_MARK = { ok: 'check', warn: 'alert', bad: 'x' };

/** The Plugins page: the state of the service, then each host the product knows
 *  with a card per attached agent, or how to attach it. Every word is the
 *  words of the server, drawn as text; a command as code. */
function renderPluginsPage(vm, failure) {
  const intro = document.getElementById('plugins-intro');
  const service = document.getElementById('plugins-service');
  const hosts = document.getElementById('plugins-hosts');
  if (!intro || !service || !hosts) return;
  // A poll that brings the same answer draws nothing again (no flicker, the
  // focus kept).
  if (vm && sameAsDrawn('plugins', vm)) return;
  clear(hosts);
  if (!vm) {
    sameAsDrawn('plugins', null);
    intro.textContent = '';
    intro.append(...cannotCheck('The Plugins page could not be read.', failure, true));
    service.hidden = true;
    return;
  }
  intro.textContent = vm.intro;
  service.hidden = false;
  service.dataset.tone = vm.service.tone;
  const head = document.getElementById('plugins-service-headline');
  clear(head);
  // A plain line (not running, nothing attached) has no mark (§4.25aj).
  const mark = PLUGIN_MARK[vm.service.tone];
  if (mark) head.append(el('span', { class: 'tone-mark' }, svg(ICON[mark], 15)));
  head.append(vm.service.headline);
  const sentence = document.getElementById('plugins-service-sentence');
  clear(sentence);
  sentence.append(textParts(vm.service.parts, ''));
  for (const h of vm.hosts || []) hosts.append(pluginHost(h));
}

/** One host: its title, what Mandu covers there, its cards or its set-up. */
function pluginHost(h) {
  const id = 'plugins-host-' + h.kind;
  const block = el('section', { class: 'block plugins-host', id, 'aria-labelledby': id + '-title', 'data-kind': h.kind },
    el('h2', { id: id + '-title', text: h.title }),
    el('p', { class: 'plugins-covers' }, textParts(h.covers, '')));
  for (const card of h.cards || []) block.append(pluginCard(card));
  if (h.setup) {
    const steps = el('ol', { class: 'plugins-setup-steps' });
    for (const cmd of h.setup.commands) steps.append(el('li', null, runCode(cmd)));
    block.append(el('div', { class: 'plugins-setup' }, el('p', { text: h.setup.sentence }), steps));
  }
  return block;
}

/** One attached agent: its state with its mark, what it means, its facts,
 *  the posture and its sentence, the cost while it runs, and its links. */
function pluginCard(c) {
  const card = el('article', { class: 'plugin-card', 'data-tone': c.tone, 'data-state': c.state, 'data-session': c.session });
  const title = el('h3', { class: 'plugin-state' }, el('span', { class: 'tone-mark' }, svg(ICON[PLUGIN_MARK[c.tone]] || ICON.alert, 14)), c.headline);
  card.append(title, el('p', { class: 'plugin-sentence' }, textParts(c.parts, '')));
  const facts = el('dl', { class: 'plugin-facts' });
  for (const f of c.facts || []) {
    facts.append(el('dt', { text: f.label }), el('dd', { 'data-tone': f.tone }, textParts(f.parts, '')));
  }
  if (Number.isFinite(c.since)) facts.append(el('dt', { text: 'Since' }), el('dd', null, whenNode(c.since)));
  card.append(facts);
  card.append(el('p', { class: 'plugin-posture' }, el('strong', { text: 'Protection here: ' + c.posture.name + '. ' }), c.posture.sentence));
  if (c.notice) {
    card.append(el('div', { class: 'exposure plugin-notice', role: 'note' },
      el('p', { class: 'posture-title', text: c.notice.headline }),
      el('p', null, textParts(c.notice.parts, ''))));
  }
  const links = el('p', { class: 'plugin-links' });
  if (c.links.session) {
    links.append(el('a', { href: routeHref('agent', c.links.session), 'data-page-link': 'agent', 'data-session': c.links.session, text: 'Open its session' }), ' · ');
  }
  const q = c.links.historyQuery;
  links.append(el('a', { href: routeHref('history') + '?' + historyParams(q, false), 'data-page-link': 'history', 'data-land': 'q:' + q, text: 'Its sessions on History' }));
  card.append(links);
  return card;
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
      for (const c of step.commands) cmds.append(el('li', {}, runCode(c.command), el('span', { class: 'dim', text: c.does })));
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

/** `grouped`: drawn under *From sessions that have ended* on Approvals, whose
 *  line says once what each ended card would say again (renderAsks).
 *  `approvals`: drawn on Approvals, where a card that is not `expanded` is
 *  Home's short card with What each answer does in place of the link to
 *  Approvals, the page it is on (dashboard.md §4.25 *An ended question is
 *  short on Approvals*, *A waiting question is short on a phone*). */
function askCard(ask, expanded, grouped, approvals) {
  const card = el('div', { class: 'ask' + (expanded ? ' expanded' : ''), 'data-id': ask.id });
  const top = el('div', { class: 'ask-top' });
  top.append(el('div', { class: 'ask-icon' }, svg(ICON[FAMILY_ICON[ask.family] || 'alert'])));
  const body = el('div', { class: 'ask-body' });
  // The headline is the heading of the card, so a screen reader jumps from
  // one question to the next (dashboard.md §4.25u *Each question and rule
  // change is a heading*): an h3 under the h2 of its section, an h4 under
  // the h3 of the ended ones. Its names are kept whole, as in the cells
  // (nameCode).
  const sentence = keepNamesWhole(el(grouped ? 'h4' : 'h3', { class: 'ask-sentence' }, ...sentenceNode(ask.sentence, '').childNodes));
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
  // Under the heading of the ended ones the card leaves its sentence out.
  // On a send of a secret, a line of its own before the link says which
  // answers cover only the next such request and which are kept until
  // changed under Rules (§4.34, *Home's card says which answers last*): the
  // short form of the expanded card's *If you click Always allow or Block*.
  const endedSaid = !!ask.askerEnded && !grouped;
  const followed = !expanded || endedSaid;
  const lasting = !expanded && ask.family === 'send' && Array.isArray(ask.answersShortParts) && ask.answersShortParts.length
    ? el('span', { class: 'ask-answers' }, askCellWords(ask.answersShortParts, ask.answersShort)) : null;
  // The toggle of a short card on Approvals is keyed by the question
  // (placeKey), so the focus stays on it when a poll draws the list again.
  const more = approvals && !expanded ? el('button', {
    type: 'button', class: 'link-btn ask-more', 'data-ask-more': ask.id, 'aria-expanded': 'false', text: 'What each answer does',
    onclick: () => openAskMore(card, ask, more.getAttribute('aria-expanded') !== 'true'),
  }) : null;
  body.append(el('div', { class: 'ask-sub' },
    expanded ? null : askCellWords(ask.whyParts, ask.why), expanded ? null : ' ',
    whenNode(ask.askedAt), ask.count > 1 && !('held' in ask) ? ', ' + ask.count + ' times' : '', askedFrom(ask), followed ? '.' : null,
    endedSaid ? el('span', { class: 'ask-ended', text: ' The agent that asked has ended, so nothing is waiting on this now. Your answer counts the next time an agent asks.' }) : null,
    lasting ? ' ' : null, lasting,
    expanded ? null : ' ', more || (expanded ? null : el('a', {
      href: routeHref('approvals', ask.id), 'data-page-link': 'approvals', 'data-ask': ask.id,
      class: 'ask-details', text: 'Details in Approvals',
    }))));
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
      const words = said.get(key) || v.label;
      const b = el('button', { type: 'button', class: 'btn' + (v.primary ? ' primary' : ''), text: words, onclick: () => answer(ask, { ...v, label: words }, card) });
      actions.append(b);
    }
  }
  if (expanded) {
    card.append(top);
    if (ask.sources && ask.sources.length) card.append(askSources(ask, card));
    card.append(...askDetail(ask));
    const foot = el('div', { style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' });
    const link = askAgentLink(ask);
    if (link) foot.append(link);
    foot.append(actions);
    card.append(foot);
  } else {
    top.append(actions);
    card.append(top);
    if (more && S.askOpen.has(ask.id)) openAskMore(card, ask, true);
  }
  return card;
}

/** What the expanded card says under its sentence: the three cells, then
 *  what Send without it and the answers that last do, each where the card
 *  offers it. A short card on Approvals opens the same (openAskMore). */
function askDetail(ask) {
  const out = [];
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
  out.push(detail);
  // What Send without it does, under the three cells (their grid stays
  // three): only on a card that offers it.
  if ((ask.actions || []).some((a) => a.strip)) out.push(el('p', { class: 'note ask-without' }, el('strong', { text: 'If you click Send without it: ' }), SEND_WITHOUT_WORDS));
  // What Always allow and Block keep doing, under it (dashboard.md §4.34,
  // *A send question says what its standing answers keep doing*): the
  // words of the server for the halves the card offers, named by its buttons.
  const standing = ask.family === 'send' && Array.isArray(ask.ifStandingParts) && ask.ifStandingParts.length ? standingHead(ask.actions) : '';
  if (standing) out.push(el('p', { class: 'note ask-standing' }, el('strong', { text: 'If you click ' + standing + ': ' }), askCellWords(ask.ifStandingParts, ask.ifStanding)));
  return out;
}

/** The link to the session that asked last, on the foot of a full card. */
function askAgentLink(ask) {
  if (!ask.sessions || !ask.sessions.length) return null;
  return askLink(ask.sessions[ask.sessions.length - 1], ask.id, 'margin-right:auto;font-size:14px');
}

/** What each answer does on a short card of Approvals (dashboard.md §4.25
 *  *An ended question is short on Approvals*, *A waiting question is short
 *  on a phone*): open, the full card's
 *  cells, its notes and its link to the agent under the card's line, in
 *  place, and the button reads Hide; closed, the short card again. Kept by
 *  question id (S.askOpen) for the next draw of the list. */
function openAskMore(card, ask, open) {
  const btn = card.querySelector('.ask-more');
  if (!btn) return;
  const had = card.querySelector('.ask-more-box');
  if (had) had.remove();
  if (open) S.askOpen.add(ask.id);
  else S.askOpen.delete(ask.id);
  card.classList.toggle('ask-open', open);
  btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  btn.textContent = open ? 'Hide' : 'What each answer does';
  if (!open) return;
  const box = el('div', { class: 'ask-more-box' }, ...askDetail(ask));
  const link = askAgentLink(ask);
  if (link) box.append(el('div', { class: 'ask-foot' }, link));
  // Before an answer's error or line, which go last on the card.
  card.querySelector('.ask-top').after(box);
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
      li.append(el('div', { class: 'note ask-source-why' }, textParts(s.noAlwaysParts, s.noAlways)));
    }
    list.append(li);
  }
  box.append(list);
  if (ask.sourcesLeft) box.append(el('p', { class: 'note ask-sources-left' }, askCellWords(ask.sourcesLeftParts, ask.sourcesLeft)));
  return box;
}

/** One Always of a send by a program: the rule of that file gains the place
 *  (`always-source`). The question stays while another file is in the way,
 *  and the card says which, with Undo it in Approvals, the link to the rule
 *  change this file's Always made (keepAnswer; until 2026-10-26 only the
 *  last file's had one); once none is (`released` from the route, never
 *  a card the poll no longer draws), the arbiter retires it and the place of
 *  the card holds an answer line (answerLine) whose link opens that rule
 *  change on Approvals with its Undo: the question was retired, not
 *  answered, so Answered earlier has no row to change. Until 2026-10-25
 *  the words of the card went with the card. */
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
  if (d.released && place && ANSWER_LINE_PLACES.has(place)) {
    if (S.approvalsAsk === ask.id) {
      S.approvalsAsk = null;
      if (S.page === 'approvals') history.replaceState(history.state, '', routeHref('approvals'));
    }
    // An older server sends no change id: the line has no link.
    const undo = changesLink(d.changeId, 'Undo it in Approvals');
    if (undo) undo.classList.add('answer-change');
    answerLine(place, card, ask, { approve: true }, undo);
  } else {
    // An older server sends no change id: the words have no link.
    const left = Array.isArray(d.left) ? d.left.map((p) => shortPath(p)) : [];
    keepAnswer(place, card, d.released
      ? 'Done: every file may go there now, so the program\'s next send goes.'
      : 'Done: ' + src.name + ' may go there now. Still in the way: ' + (left.join(', ') || 'another file') + '.', true, d.changeId);
  }
  answerWorked(place, card);
  AGENT_READS.wrote();
  forgetDrawn();
  await loadHome();
  if (S.page === 'rules') loadRules();
}

/** The buttons of the standing answers a card offers ("Always allow or
 *  Block", "Always allow", "Block"): an approve, and a deny that is not
 *  Send without it, neither scoped `once`. A card from an older server that
 *  lists no answers offers both, as its buttons do. Empty when it offers
 *  neither. */
function standingHead(actions) {
  const list = actions || [];
  const allow = list.length ? list.find((a) => a.approve && a.scope !== 'once') : { label: 'Always allow' };
  const block = list.length ? list.find((a) => !a.approve && a.scope !== 'once' && !a.strip) : { label: 'Block' };
  return [allow, block].filter(Boolean).map((a) => a.label).join(' or ');
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
  answerLine(place, card, ask, verb);
  answerWorked(place, card);
  // The agent page reads it again after (loadHome): a read of it asked
  // before this answer still has the question waiting (readsInOrder).
  AGENT_READS.wrote();
  forgetDrawn();
  await loadHome();
  if (S.page === 'rules') loadRules();
}
let askErrorSeq = 0;
/** `link`: a node after the words (the change an answer made on a card no
 *  poll draws, keepAnswer). */
function showAskError(card, text, link) {
  for (const b of card.querySelectorAll('button, select')) b.disabled = false;
  // Allow on an over-broad change stays off until ALLOW is typed, also after
  // a refusal (the poll no longer redraws the card that would turn it off).
  const typed = card.querySelector('.proposal-confirm');
  const allow = card.querySelector('.proposal-allow');
  if (typed && allow) allow.disabled = !typedAllow(typed.value);
  let e = card.querySelector('.ask-error');
  // Its id: the button pressed, given the focus back, is described by it
  // (focusAnswered).
  if (!e) { e = el('div', { class: 'ask-error', id: 'ask-error-' + (++askErrorSeq) }); card.append(e); }
  setWords(e, text);
  if (link) e.append(' ', link);
}

/** What a held message's answer did, by its answer and scope, led by the
 *  words Answered earlier says it with (ANSWERED_OUTCOME_WORDS), then what
 *  the AI reads: from its next request when the request already went. */
const PROMPT_ANSWERED = {
  'send once': 'Sent as written: the AI reads your message as you wrote it.',
  'send session': 'Sent as written for this session: the AI reads your message as you wrote it.',
  'mask once': 'Sent masked: the AI reads your message with that part masked.',
  'cancel once': 'Cancelled: the AI does not read your message.',
};
/** After an answer that worked, the list its card was in (Home's Approvals
 *  waiting, Approvals' Waiting for your answer, the session page's Needs
 *  your OK) shows one line where the card was (dashboard.md §4.25 *An
 *  answer says what it did*): what you chose and about what, the one thing
 *  left to do (the ask's `afterAllow`: "Tell Claude Code to try again.",
 *  "The program goes on now."; a blocked send, "Nothing was sent."), and
 *  Change your answer, which opens the answered row on Approvals
 *  (markApprovalsAsk), or See your answer after why, when that row offers
 *  no change (keptAnswerWords, since 2026-10-28). It names only what the card named. Until 2026-10-22
 *  the card just went: a person who answered from Home never read the
 *  card's "tell the agent to try again", and waited for an agent that would
 *  not try again on its own. The line replaces the place's last one, is
 *  put back by each draw of its list (putAnswerLine) at the rank its card
 *  had, and goes with the page (dropAnswerLines). `link`: the link of the
 *  line in place of Change your answer (the last Always of a send by a program:
 *  Undo it in Approvals, alwaysSource), null for none. A verb with its own
 *  `head` brings the words of the line (`words`, nodes, and `after`):
 *  those of a rule change (proposalLine). */
function answerLine(place, card, ask, verb, link) {
  if (!place || !ANSWER_LINE_PLACES.has(place)) return;
  dropAnswerLine(place);
  const list = document.getElementById(ANSWER_PLACES[place]);
  const rank = Math.max(0, [...drawnCards(list).keys()].indexOf(card.dataset.id));
  const ended = !!ask.askerEnded;
  const node = el('div', { class: 'answer-line', role: 'status', 'data-answer-line': place });
  if (verb.prompt) node.append(PROMPT_ANSWERED[verb.prompt + ' ' + (verb.scope || 'once')] || 'Answered.');
  else if (verb.head) node.append(el('strong', { text: verb.head + ':' }), ' ', ...verb.words, verb.after ? ' ' + verb.after : '');
  else {
    const allowed = verb.approve || verb.strip;
    const head = verb.strip ? 'Allowed without the secret'
      : !verb.approve ? 'Blocked'
        : verb.scope === 'once' ? 'Allowed once'
          : verb.label === 'Allow this session' ? 'Allowed for this session' : 'Always allowed';
    const what = Array.isArray(ask.whatParts) && ask.whatParts.length ? ask.whatParts : ask.sentence;
    const after = !allowed ? (ask.family === 'send' ? 'Nothing was sent.' : '')
      // The agent that asked has ended: none tries again (the card said so).
      : ask.askerEnded ? 'Your answer counts the next time an agent asks.'
        : typeof ask.afterAllow === 'string' ? ask.afterAllow : '';
    const said = (what || []).map((p) => p.text).join('');
    node.append(el('strong', { text: head + ':' }), ' ', askCellWords(what, said), /[.!?]$/.test(said) ? '' : '.', after ? ' ' + after : '');
  }
  // An answer its row on Approvals cannot change (Send without it, and the
  // ask the server marks `reversible` false): why, and See your answer.
  const kept = link === undefined && (!!verb.strip || ask.reversible === false);
  if (kept) node.append(' ', keptAnswerWords(verb));
  const to = link !== undefined ? link
    : el('a', { href: routeHref('approvals', ask.id), 'data-page-link': 'approvals', 'data-ask': ask.id, class: 'answer-change', text: kept ? 'See your answer' : 'Change your answer' });
  if (to) node.append(' ', to);
  S.answerLines.set(place, { id: ask.id, rank, ended, visit: S.visit, node });
}
/** Why an answer its row on Approvals offers no change of stays as it is
 *  (answerLine; policy-panel.ts answerHasReversal): a held message answered
 *  for that message, Send without it, a session answer to a held message
 *  (its own row for the session flips it), and a HIGH session ask, whose
 *  answer is kept in Rules. */
function keptAnswerWords(verb) {
  if (verb.prompt) return verb.scope === 'session' ? 'To change it, use the row for the session in Answered earlier.' : 'It applied to that message only.';
  if (verb.strip) return 'It applied to that request only.';
  return 'To change it, remove it in Rules.';
}
/** The places whose waiting questions leave a line once answered, and
 *  the rule changes on Approvals (decideProposal). */
const ANSWER_LINE_PLACES = new Set(['home', 'approvals', 'agent', 'proposal']);
/** After each draw of `place` into `list`: its line, back where its card
 *  was (before the card now at that rank, else after the last card, else
 *  first, above "Nothing is waiting for you."), in the group of its card: the
 *  line of a live card stays above the heading of the ended ones (renderAsks).
 *  One left from another visit of the page goes. */
function putAnswerLine(place, list) {
  const a = S.answerLines.get(place);
  if (!a) return;
  if (a.visit !== S.visit || !list) { dropAnswerLine(place); return; }
  const cards = [...drawnCards(list).values()];
  let before = cards[a.rank] || (cards.length ? cards[cards.length - 1].nextSibling : list.firstChild);
  const head = before && before.previousElementSibling;
  if (!a.ended && head && head.classList.contains('ask-group-head')) before = head;
  if (before !== a.node) list.insertBefore(a.node, before || null);
}
function dropAnswerLine(place) {
  const a = S.answerLines.get(place);
  if (a) a.node.remove();
  S.answerLines.delete(place);
}
/** The page changed: every line goes with it. Rule changes your agent
 *  asked for, shown for its line alone (renderProposals), hides with it,
 *  not at the next poll. */
function dropAnswerLines() {
  const proposal = S.answerLines.has('proposal');
  for (const place of [...S.answerLines.keys()]) dropAnswerLine(place);
  if (proposal && !S.proposals.length) document.getElementById('approvals-proposals-block').hidden = true;
}
/** The line `place` shows now, if any (the session page keeps Needs your
 *  OK shown under it). */
function hasAnswerLine(place) {
  const a = S.answerLines.get(place);
  return !!a && a.visit === S.visit;
}

/** The waiting questions of a list. `changesWait`: a rule change waits too
 *  (Home and Approvals pass S.proposals), so an empty list says no question
 *  waits, never "Nothing" under the "Approvals waiting (1)" and the nav
 *  badge that count it (dashboard.md §4.25 *An empty list never says
 *  nothing waits over a rule change*). `order` (Home and Approvals): the
 *  questions an agent waits on come first, those from sessions that have
 *  ended after, each newest first as the server lists them, so the three of
 *  Home are the ones holding an agent up; `grouped` (Approvals) also puts the
 *  ended ones under a heading of their own when some, not all, have ended
 *  (dashboard.md §4.25 *A question from a session that has ended*). The
 *  heading has no data-id: no card to drawnCards. Under it a card is short
 *  (askFolds). */
function renderAsks(host, home, expanded, changesWait, order) {
  clear(host);
  if (!home || !home.waitingKnown) {
    // Mandu is not running at all (§4.25 *Protection is off when nothing
    // runs*): never a fault. That none waits is said only where Mandu never
    // ran here (the setup card): the questions of an earlier run are kept,
    // and come back when it starts again.
    if (home && home === S.home && notRunningNow()) {
      host.append(el('div', { class: 'empty waiting-off' }, ...(home.firstRun
        ? ['No agent runs with Mandu now, so none is waiting for your answer. Mandu starts with your first agent: ', ...startCodes(home), '.']
        : cannotCheck('', 'not-running', false, 'questions waiting for your answer show here'))));
      return;
    }
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
  // The session page (order 'agent') keeps its own order: no heading of
  // the ended ones.
  const waiting = !order || order === 'agent' ? home.waiting
    : [...home.waiting.filter((a) => !a.askerEnded), ...home.waiting.filter((a) => a.askerEnded)];
  const shown = expanded ? waiting : waiting.slice(0, HOME_ASK_CAP);
  const head = order === 'grouped' ? shown.findIndex((a) => a.askerEnded) : -1;
  shown.forEach((ask, i) => {
    if (i === head && i > 0) {
      host.append(el('div', { class: 'ask-group-head' },
        el('h3', { text: 'From sessions that have ended' }),
        el('p', { class: 'note', text: 'No agent is waiting on these now. Your answer decides what happens the next time an agent asks the same.' })));
    }
    const grouped = head > 0 && i >= head;
    // On a phone every card of Approvals may be short, not only the ended
    // ones, and so may every card of a session page's Needs your OK
    // (dashboard.md §4.25 *A waiting question is short on a phone*): there
    // too a short card opens What each answer does in place.
    const agent = order === 'agent';
    const short = (order === 'grouped' && (grouped || onPhone())) || (agent && onPhone());
    host.append(askCard(ask, expanded && !(short && askFolds(ask, agent)), grouped, order === 'grouped' || agent));
  });
  // An open card that left the list is forgotten: only by Approvals, whose
  // list is every question (a session page lists its own only).
  if (order === 'grouped') for (const id of S.askOpen) if (!home.waiting.some((a) => a.id === id)) S.askOpen.delete(id);
  if (shown.some((a) => a.family === 'prompt')) {
    void loadPromptHolds().then((holds) => { if (holds) fillPromptFound(host, holds); });
  }
  const more = home.waiting.length - shown.length;
  const ended = order === 'live first' ? waiting.slice(shown.length).filter((a) => a.askerEnded).length : 0;
  if (more > 0) host.append(el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', class: 'more', text: moreAsks(more, ended) }));
}

/** Whether a card under *From sessions that have ended* on Approvals, or
 *  any card of Approvals on a phone, is drawn short (dashboard.md §4.25 *An
 *  ended question is short on Approvals*, *A waiting question is short on a
 *  phone*): not a held message nor a program's send of the files it
 *  holds, whose answers need the detail, and not the card the page was
 *  opened for (`/approvals/<id>`), which is full and, once the mark is gone,
 *  short with What each answer does open, never folded under the reader.
 *  On a session page (`agent`), not the question its See what the agent was
 *  doing link opened it for (`/agents/<id>?ask=<question id>`, S.agentAsk),
 *  which stays full for the visit. */
function askFolds(ask, agent) {
  if (ask.family === 'prompt' || (ask.sources && ask.sources.length)) return false;
  if (agent) return S.agentAsk !== ask.id;
  if (S.approvalsAsk !== ask.id) return true;
  S.askOpen.add(ask.id);
  return false;
}

/** The ended question `/approvals/<id>` names, while it waits (on a phone,
 *  any question it names): its card is drawn full, so the list is drawn
 *  again when the mark comes or goes (renderApprovals). */
function markedEnded(home) {
  const id = S.approvalsAsk;
  if (!id || !home || !home.waitingKnown) return null;
  return home.waiting.some((a) => a.id === id && (a.askerEnded || onPhone())) ? id : null;
}

/** The page's phone breakpoint (app.css `max-width: 760px`), where every
 *  card of Approvals is short but those askFolds keeps full (dashboard.md
 *  §4.25 *A waiting question is short on a phone*). A browser without
 *  matchMedia reads as wide: its cards are drawn as before. */
const PHONE = typeof window.matchMedia === 'function' ? window.matchMedia('(max-width: 760px)') : null;
function onPhone() { return !!PHONE && PHONE.matches; }
/** Turning the phone, or a window resized past the breakpoint, draws
 *  Approvals and a session page's Needs your OK again in the other form:
 *  only when the query flips (its `change`), never on every resize. Open
 *  cards stay open (S.askOpen) and the focus stays where it was, as over a
 *  poll (pollPlace). The session page draws only that block, from the data
 *  it last drew, so the story stays as it is; a poll that brings the same
 *  then leaves it as drawn. */
function phoneFlipped() {
  const place = pollPlace(document.getElementById('main'));
  if (S.home) markApprovalsAsk();
  const shown = S.agentWaitingShown;
  if (S.page === 'agent' && shown && shown.visit === S.visit && shown.id === S.agentId) drawAgentWaiting(shown.vm, shown.id);
  pollRefocus(place);
}
if (PHONE) {
  if (typeof PHONE.addEventListener === 'function') PHONE.addEventListener('change', phoneFlipped);
  else if (typeof PHONE.addListener === 'function') PHONE.addListener(phoneFlipped);
}

/** The words of the link under the three questions of Home, which says how
 *  many of the hidden ones are from sessions that have ended (dashboard.md
 *  §4.25 *The order of the lists*): Home draws those last, so the hidden
 *  rest is often only questions no agent waits on. The words follow the
 *  heading of Approvals, so the person finds them under it. */
function moreAsks(more, ended) {
  const words = n(more, 'more question', 'more questions') + ' in Approvals';
  if (!ended) return words;
  if (ended === more) return words + (more === 1 ? ', from a session that has ended' : ', all from sessions that have ended');
  return words + ', ' + (ended === 1 ? '1 from a session that has ended' : ended + ' from sessions that have ended');
}

function renderAgents(home) {
  const host = document.getElementById('home-agents');
  const hist = document.getElementById('home-history');
  hist.href = routeHref('history');
  const shown = home ? home.agents.filter((a) => a.state !== 'idle') : [];
  S.homeRows.agents = shown;
  moveLastSteps(host, shown);
  if (sameAsDrawn('agents', home ? [home.history.total, startList(home), shown.map(liveDrawnFrom)] : ['failed', S.homeFailure])) return;
  if (!home) {
    hist.textContent = '';
    keepRows(host, [el('div', { class: 'empty' }, ...cannotCheck('Could not check which agents are running.', S.homeFailure, false))]);
    return;
  }
  hist.textContent = home.history.total ? 'History: ' + n(home.history.total, 'session', 'sessions') : '';
  if (!shown.length) {
    keepRows(host, [el('div', { class: 'empty' }, 'No agent is running right now. Start one with ',
      ...startCodes(home), '.')]);
    return;
  }
  keepRows(host, shown.map((a) => keptRow(a, 'startedAt', () => {
    const dot = el('span', { class: 'dot ' + (!a.holds ? 'bad' : a.state === 'waiting' || rowWarn(a) ? 'warn' : 'ok') });
    // A row waiting for your OK keeps what you asked, as History's does: the
    // amber dot and the count that leads its counts say it waits
    // (dashboard.md §4.25 *Agents, not sessions*).
    const what = promptLine(a, 'No prompt yet');
    const bits = rowMarks(a);
    if (a.waiting) bits.push(waitingLink(a));
    bits.push(...rowCounts(a));
    return agentRow(a, dot, what, countsLine('sub', bits), liveWhen(a));
  }, liveDrawnFrom(a))));
}

/** When a running row's agent last did something (`lastAt`, its last
 *  event), or NaN when that says nothing more than its start: not known, or
 *  within a minute of `startedAt` (a session that has only just begun). */
function lastStepMs(a) {
  const start = a.startedAt ? Date.parse(a.startedAt) : NaN;
  const last = a.lastAt ? Date.parse(a.lastAt) : NaN;
  return Number.isFinite(start) && Number.isFinite(last) && last - start > 60_000 ? last : NaN;
}

/** A running row's moment (dashboard.md §4.25 *Agents, not sessions*):
 *  "started 6 hours ago · last step 2 minutes ago" under Running now,
 *  "running now, started 6 hours ago · last step 2 minutes ago" on History
 *  (`verb`, the words whenLine puts before the start), so a session left
 *  open in a forgotten terminal does not read like one working now; the
 *  start alone when lastStepMs has nothing to add. The dot ends the first
 *  `.when-phrase` and "last step" opens the second, so a narrow column
 *  breaks only between them. The second moment is `time.agent-last`, which
 *  moveLastSteps keeps current without drawing the row again. Its phrase is
 *  a link to the session at its newest turn (`?go=latest`, §4.25 *A live
 *  row names its last step*), named by agentRow. */
function liveWhen(a, verb = 'started') {
  const line = whenLine('agent-started', verb, a.startedAt);
  const ms = lastStepMs(a);
  if (!line || !Number.isFinite(ms)) return line;
  line.lastChild.append(' ·');
  line.append(' ', el('a', { class: 'when-phrase agent-last-link', href: routeHref('agent', a.id, null, 'latest'), 'data-page-link': 'agent', 'data-session': a.id, 'data-land': 'latest' },
    'last step ', el('time', { class: 'ago agent-last', datetime: new Date(ms).toISOString(), title: clockWords(ms), text: ago(ms) })));
  return line;
}
/** The name of the "last step" link of a running row: its words, where
 *  it goes and its row (`data-about`, agentRow), as the "last step" button
 *  in the header of the session page is named (lastStepName): "Last step 2
 *  minutes ago: go to the latest turn of Claude Code, Fix the test in ~/ws".
 *  Kept in step with its words by moveLastSteps and refreshWhen. */
function nameLastStepLink(link) {
  const t = link.querySelector('time.agent-last');
  const ms = t ? Date.parse(t.getAttribute('datetime')) : NaN;
  if (!Number.isFinite(ms)) return;
  link.setAttribute('aria-label', lastStepName(ms) + (link.dataset.about ? ' of ' + link.dataset.about : ''));
}

/** What a running row is drawn from (Running now, and History while it
 *  runs): rowDrawnFrom without `lastAt`, so
 *  a working agent's next step does not draw its row again (*The rows you
 *  read stay still*), with only whether it names a last step at all. */
function liveDrawnFrom(a) {
  return { ...rowDrawnFrom(a, 'startedAt'), stepped: Number.isFinite(lastStepMs(a)) };
}

/** Every poll, before Running now or History decides whether to draw: each
 *  row kept in place takes its agent's last step into its `time.agent-last`
 *  (its datetime, its words, its clock on hover), so the moment moves while
 *  the row and a focused Details stay as they are. `shown` is every row the
 *  list holds, the pages Show more brought included. */
function moveLastSteps(host, shown) {
  for (const a of shown) {
    const ms = lastStepMs(a);
    if (!Number.isFinite(ms)) continue;
    const row = [...host.children].find((x) => x.dataset.session === a.id);
    const t = row && row.querySelector('time.agent-last');
    const iso = new Date(ms).toISOString();
    if (!t || t.getAttribute('datetime') === iso) continue;
    t.setAttribute('datetime', iso);
    t.textContent = ago(ms);
    t.title = clockWords(ms);
    const link = t.closest('a.agent-last-link');
    if (link) nameLastStepLink(link);
  }
}

/** A session row's first line under Running now, Earlier and History: what
 *  you asked (`none` when no prompt is known), then " in ~/folder" where it
 *  ran, both whole on hover, so a session reads the same in the three lists
 *  (dashboard.md §4.25 *Agents, not sessions*). The folder is what tells
 *  two sessions of one agent apart, so it stays in sight (*The folder stays
 *  in sight*): a long prompt is cut before it, and a folder past half the
 *  line is cut at its start by app.css (`.prompt-folder`, right to left
 *  around a left-to-right `bdi`, so "~" and "/" stay in place). The words
 *  stay whole in the page, so the row's name (lineWords) is as before. */
function promptLine(a, none) {
  const what = a.cwd
    ? el('div', { class: 'sub prompt-line' }, el('span', { class: 'prompt-text', text: a.title || none }),
      el('span', { class: 'prompt-in', text: ' in ' }), el('code', { class: 'prompt-folder' }, el('bdi', { dir: 'ltr', text: shortPath(a.cwd) })))
    : el('div', { class: 'sub ellipsis', text: a.title || none });
  what.title = (a.title || '') + (a.cwd ? ' — ' + a.cwd : '');
  return what;
}

/** What each row keepRows left or made was drawn from (keptRow's `from`). */
const ROW_DRAWN = new WeakMap();
/** A row of a session list for keepRows: its session, what it is drawn
 *  from (`drawn`, else rowDrawnFrom with the list's moment, the key
 *  sameAsDrawn reads), and how to draw it. */
function keptRow(a, moment, make, drawn) {
  return { key: a.id, from: JSON.stringify(drawn || rowDrawnFrom(a, moment)), make };
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
  row.append(el('div', { class: 'name' }, dot, a.agent, a.preview ? agentPreviewMark(a.preview) : null, a.notice ? agentNoticeMark(a.notice, a.noticeParts) : null));
  row.append(el('div', { class: 'agent-what' }, what, counts));
  row.append(el('div', { class: 'dim agent-when' }, when));
  const about = [a.agent, lineWords(what)].filter(Boolean).join(', ');
  const link = agentLink(a.id, 'Details');
  link.setAttribute('aria-label', rowControlName('Details', about));
  row.append(link);
  const last = row.querySelector('a.agent-last-link');
  if (last) { last.dataset.about = about; nameLastStepLink(last); }
  const waits = row.querySelector('a.agent-waiting-link');
  if (waits) waits.setAttribute('aria-label', rowControlName(lineWords(waits), about));
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
    el('span', { class: 'when-phrase' }, verb.slice(cut) + ' ', agoNode(ms)));
}
/** A moment in relative words, the clock time on hover, kept current by
 *  refreshWhen: <time class="ago" datetime="ISO" title="Sep 30, 14:12">3 hours ago</time>. */
function agoNode(ms) {
  return el('time', { class: 'ago', datetime: new Date(ms).toISOString(), title: clockWords(ms), text: ago(ms) });
}

/** What leads the counts line of a session row (dashboard.md §4.25 *A session
 *  that ran with protection off says so*): "protection failed", then
 *  "protection was off" when the session recorded the `off` mode (never
 *  the setting now; a session with no recorded mode says nothing), then
 *  "less protection than usual" when a protection did not start in it
 *  (§4.21). A row that has any has the dot of it (rowWarn): red, else amber. */
function rowMarks(a) {
  const bits = [];
  if (!a.holds) bits.push('protection failed');
  if (a.protectionOff) bits.push('protection was off');
  if (a.lessProtection) bits.push('less protection than usual');
  return bits;
}
/** Whether a protected row has the amber dot for what it ran without:
 *  protection off, or a protection that did not start (rowMarks); or for
 *  a change to a secret file Mandu did not apply (notAppliedLink). */
function rowWarn(a) {
  return !!(a.protectionOff || a.lessProtection || a.notApplied > 0);
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
 *  number with its word (countWords); null with none. A bit may be a node
 *  (waitingLink), drawn as it is between the commas. */
function countsLine(tone, bits) {
  if (!bits.length) return null;
  const line = el('div', { class: tone + ' agent-counts' });
  let words = '';
  bits.forEach((b, i) => {
    words += (i ? ', ' : '') + (typeof b === 'string' ? b : '');
    if (typeof b === 'string') return;
    if (words) line.append(countWords(words));
    line.append(b);
    words = '';
  });
  if (words) line.append(countWords(words));
  return line;
}
/** The "1 question waiting for you" of a row (dashboard.md §4.25 *Agents, not
 *  sessions*): a link to the session at Needs your OK (`?go=waiting`, as
 *  its waiting tile goes), named by its row in agentRow. */
function waitingLink(a) {
  return el('a', { class: 'agent-waiting-link', href: routeHref('agent', a.id, null, 'waiting'), 'data-page-link': 'agent', 'data-session': a.id, 'data-land': 'waiting' },
    countWords(n(a.waiting, 'question waiting for you', 'questions waiting for you')));
}

/** The "changes to 1 file not applied" of an ended row (dashboard.md
 *  §4.25b *Home and History say so*): a link to the session at Changes
 *  Mandu did not apply to your files (`?go=not-applied`), the files named
 *  only there. null with none (or an older server). */
function notAppliedLink(a) {
  const k = typeof a.notApplied === 'number' && Number.isFinite(a.notApplied) ? Math.floor(a.notApplied) : 0;
  if (k <= 0) return null;
  return el('a', { class: 'agent-not-applied-link', href: routeHref('agent', a.id, null, 'not-applied'), 'data-page-link': 'agent', 'data-session': a.id, 'data-land': 'not-applied' },
    countWords('changes to ' + n(k, 'file', 'files') + ' not applied'));
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
 *  still holds yesterday evening's sessions. The first EARLIER_SHOWN and
 *  every one where protection failed, and every one after "Show them"
 *  until the page changes (§4.25ad: the server sends them all). */
function renderEarlier(home) {
  const block = document.getElementById('home-earlier-block');
  const host = document.getElementById('home-earlier');
  const idle = home ? home.agents.filter((a) => a.state === 'idle') : [];
  const span = home ? windowWords(home) : '';
  // A row where protection failed is never cut (the hero says "marked
  // "protection failed" in the lists below", §4.25ad).
  const shown = S.earlierAll === S.visit ? idle : idle.filter((a, i) => i < EARLIER_SHOWN || !a.holds);
  S.homeRows.earlier = shown;
  if (sameAsDrawn('earlier', home ? [span, idle.length, shown.map((a) => rowDrawnFrom(a, 'lastAt'))] : 'failed')) return;
  // Not known: Running now above says so once.
  if (!home) { keepRows(host, []); block.hidden = true; return; }
  block.hidden = idle.length === 0;
  document.getElementById('home-earlier-title').textContent = span ? 'Earlier ' + span : 'Earlier';
  const parts = shown.map((a) => keptRow(a, 'lastAt', () => {
    const what = promptLine(a, 'No prompt reached the AI');
    const bits = rowMarks(a);
    bits.push(...rowCounts(a));
    // A change to a secret file Mandu did not apply: its page lists the files.
    const lost = notAppliedLink(a);
    if (lost) bits.push(lost);
    // A question it asked before it ended still waits in Approvals.
    if (a.waiting) bits.push(waitingLink(a));
    return agentRow(a, el('span', { class: 'dot' + (!a.holds ? ' bad' : rowWarn(a) ? ' warn' : '') }), what,
      countsLine('dim', bits),
      whenLine('agent-ended', 'ended', a.lastAt));
  }));
  const rest = idle.length - shown.length;
  if (rest > 0) {
    // The rest, in place: the first of them takes the focus (showRest).
    parts.push(showRest(el('div', { class: 'row dim earlier-more' }), n(rest, 'more session', 'more sessions') + (span ? ' ' + span : '') + '.', [], rest, () => {
      const before = new Set(shown.map((a) => a.id));
      S.earlierAll = S.visit;
      renderEarlier(S.home);
      renderHomeMeanings();
      const first = host.children[idle.findIndex((a) => !before.has(a.id))];
      if (first) landOn(first);
    }));
  }
  keepRows(host, parts);
}

/** Home's *What the counts mean* (dashboard.md §4.25 *What the counts
 *  mean*, *Home's fold*): under Earlier (under Running now when Earlier is
 *  hidden), for the rows both lists drew (S.homeRows, kept by renderAgents
 *  and renderEarlier before their sameAsDrawn returns, so one list's
 *  unchanged rows still count). Hidden when the read failed. */
function renderHomeMeanings() {
  drawRowMeanings(document.getElementById('home-count-meanings'), [...S.homeRows.agents, ...S.homeRows.earlier]);
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
  // sessions the reads of the switch looked through. `day`: the day it lists
  // from, back (*Go to a day*), read as `before=` by each of them too.
  if (!more) S.history = { visit, q: S.historyQ || '', only: !!S.historyOnly, day: S.historyDay || '', rows: [], next: null, total: 0, all: 0, through: 0, failure: null, out: 0, homeAt: 0 };
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
    S.history.of = historyOf(r);
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
  let query = r && r.query;
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
    query = more.query || query;
  }
  return { ...r, rows, next, total, ...(only ? { only } : {}), ...(query ? { query } : {}) };
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
  if ((b.top < barRoom() || b.bottom > window.innerHeight) && row.scrollIntoView) row.scrollIntoView({ block: 'center' });
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
  if (r) Object.assign(h, historyFollowed(h, r), { total: r.total || 0, all: historyAll(r), of: historyOf(r), failure: null });
  else if (h.rows.length) return;
  else h.failure = failure;
  const place = pollPlace(document.getElementById('main'));
  if (renderHistory(host, true)) pollRefocus(place);
}
/** A History read: `query` its `?after=`/`?limit=` part (or ''), with the
 *  search `h.q`, the switch `h.only` and the day `h.day` (as `before=`, the
 *  moment the next day starts, historyDayEnd) the list was opened with,
 *  when it has them. */
function historyRead(query, h) {
  const more = [historyParams(h.q, h.only), h.day ? 'before=' + historyDayEnd(h.day) : ''].filter(Boolean).join('&');
  return 'home/history' + query + (more ? (query ? '&' : '?') + more : '');
}
/** The search, switch and day of History as the query of an address (no
 *  `?`), or ''. */
function historyParams(q, only, day) {
  return [q ? 'q=' + enc(q) : '', only ? 'only=' + ONLY_STEPPED_IN : '', day ? 'day=' + day : ''].filter(Boolean).join('&');
}
/** How many sessions a read with the switch on looked through, from the
 *  newest (`only.through`), or a search that stopped short of the oldest
 *  (`query.through`, §4.25ae *By a secret or a host*); 0 without either. */
function historyThrough(r) {
  return r.only && Number.isFinite(r.only.through) ? r.only.through
    : r.query && Number.isFinite(r.query.through) ? r.query.through : 0;
}
/** How many sessions a search could look through (`query.of`: those on
 *  record, cut at the day when one is set); 0 without a search. */
function historyOf(r) {
  return r.query && Number.isFinite(r.query.of) ? r.query.of : 0;
}
/** Every session on record, as a read says it: `query.all` when it was
 *  found by a search, `before.all` when it was cut at a day, else its
 *  `total`. */
function historyAll(r) {
  return r.query && Number.isFinite(r.query.all) ? r.query.all
    : r.before && Number.isFinite(r.before.all) ? r.before.all : r.total || 0;
}

// ── Go to a day (dashboard.md §4.25ae) ──────────────────────────────────────
/** A day as the History address carries it ("2026-10-20", a real date),
 *  or ''. */
function historyDayParam(v) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(String(v || ''));
  if (!m) return '';
  const d = new Date(+m[1], +m[2] - 1, +m[3], 12);
  return d.getFullYear() === +m[1] && d.getMonth() === +m[2] - 1 && d.getDate() === +m[3] ? m[0] : '';
}
/** The moment the local day after `day` starts, in epoch ms: the
 *  `before=` of History, so the server needs no time zone. Built from the
 *  parts of the date, so a day 23 or 25 hours long (a clock change) ends where it
 *  does, never 86 400 000 ms on. */
function historyDayEnd(day) {
  const [y, m, d] = day.split('-').map(Number);
  return new Date(y, m - 1, d + 1).getTime();
}
/** The words of a day inside a sentence: "Tuesday, Oct 20", "yesterday". */
function historyDayWords(day) {
  const w = dayWords(day);
  return w === 'Today' || w === 'Yesterday' ? w.toLowerCase() : w;
}
/** The local calendar day `by` days from `day` ("2026-10-20", -1 gives
 *  "2026-10-19"). Built from the parts of the date at noon, so a day 23 or
 *  25 hours long (a clock change) steps to the next date, never 86 400 000
 *  ms on. */
function historyDayStep(day, by) {
  const [y, m, d] = day.split('-').map(Number);
  return localDay(new Date(y, m - 1, d + by, 12).getTime()).key;
}
/** The box as the day of the page says it: its value, today as its latest
 *  day (no earliest: how long sessions are kept is a setting), and while a
 *  day is set Day before, Day after (not on today or later, the box max)
 *  and Show the newest beside it. Each step button is named by its own
 *  words then the day it goes to ("Day before: Monday, Oct 19"), so its
 *  name starts with what it shows (WCAG 2.5.3). */
function showHistoryDay() {
  const box = document.getElementById('history-day');
  if (box.value !== S.historyDay) box.value = S.historyDay;
  box.max = localDay(Date.now()).key;
  document.getElementById('history-newest').hidden = !S.historyDay;
  const before = document.getElementById('history-day-before');
  const after = document.getElementById('history-day-after');
  before.hidden = !S.historyDay;
  after.hidden = !S.historyDay || S.historyDay >= box.max;
  if (!before.hidden) before.setAttribute('aria-label', 'Day before: ' + historyDayWords(historyDayStep(S.historyDay, -1)));
  else before.removeAttribute('aria-label');
  if (!after.hidden) after.setAttribute('aria-label', 'Day after: ' + historyDayWords(historyDayStep(S.historyDay, 1)));
  else after.removeAttribute('aria-label');
}
/** Day before (`by` -1) or Day after (+1): the day a calendar day on, as
 *  choosing it in the box does (setHistoryDay). The focus stays on the
 *  pressed button; when Day after reaches today and hides, it moves to
 *  Day before, never to the page. */
function stepHistoryDay(by) {
  if (!S.historyDay) return;
  setHistoryDay(historyDayStep(S.historyDay, by));
  const pressed = document.getElementById(by < 0 ? 'history-day-before' : 'history-day-after');
  (pressed.hidden ? document.getElementById('history-day-before') : pressed).focus();
}
/** A day chosen in the box, or '' (cleared, or Show the newest): the list
 *  starts over from it, as a search that changed does, and the address says
 *  so (replaced, not pushed). Only the list is drawn again. */
function setHistoryDay(day) {
  if (S.page !== 'history') return;
  const next = historyDayParam(day);
  if (next === S.historyDay && S.history && S.history.day === next) return;
  S.historyDay = next;
  showHistoryDay();
  const href = stateHref();
  if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
  loadHistory(false);
}
/** Show the newest: no day, every session from the newest, the box
 *  focused (as Clear focuses the search box). */
function showHistoryNewest() {
  setHistoryDay('');
  document.getElementById('history-day').focus();
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
  // A date box fires `change` once a whole day is chosen or it is cleared.
  const day = document.getElementById('history-day');
  day.addEventListener('change', () => setHistoryDay(day.value));
  document.getElementById('history-day-before').addEventListener('click', () => stepHistoryDay(-1));
  document.getElementById('history-day-after').addEventListener('click', () => stepHistoryDay(1));
  document.getElementById('history-newest').addEventListener('click', showHistoryNewest);
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
  moveLastSteps(host, h.rows);
  const same = sameAsDrawn('history', [h.q, h.only, h.day, h.total, h.all, h.of, h.next, h.through, h.failure, h.rows.length ? null : [startList(S.home), offKey()], h.rows.map(historyDrawnFrom)]);
  if (poll && same) return false;
  h.drawn = true;
  // What the counts mean follows the rows on every branch below: none
  // drawn (an empty list, a failed read) hides it.
  drawRowMeanings(document.getElementById('history-count-meanings'), h.rows);
  // A read that failed because Mandu is not running at all (offCause), with
  // nothing drawn and no search, switch or day: where Mandu never ran here
  // (the setup card), the record is empty, and the list says so as an
  // empty record does, its box hidden; where it ran before, that its
  // sessions show here once it starts (§4.25 *Protection is off when
  // nothing runs*).
  const off = !h.rows.length && !!h.failure && !h.q && !h.only && !h.day && offCause(h.failure) === 'not-running';
  const never = off && !!S.home.firstRun;
  // Nothing on record at all, and no search or switch to undo: there is
  // nothing to find, so no box (§4.25ae *An empty History has nothing to
  // find*); the poll that brings the first session brings it back. A read
  // that failed does not say the record is empty, and a box that holds the
  // focus (emptied, to an empty record) stays.
  const form = document.getElementById('history-search');
  if (!h.failure || never) form.hidden = !h.q && !h.only && !h.day && (never || h.all === 0) && !form.contains(document.activeElement);
  // A search's count: "3 of 214 sessions" (none without a search). With
  // the switch, what the list keeps: how many it keeps is not known before
  // every session is read. A search that finds none has the sentence of
  // the list there, said to a screen reader only (findCount).
  // A day (§4.25ae *Go to a day*) adds where the list starts, "from
  // Tuesday, Oct 20 back", and its none says the day.
  // A search that stopped short of the oldest session (§4.25ae *By a
  // secret or a host*) says how far it looked, never that none matches.
  const capped = !!h.q && !h.only && h.through > 0;
  const counted = (!!h.q || h.only || !!h.day) && h.rows.length > 0;
  const onDay = h.day ? ' on or before ' + historyDayWords(h.day) : '';
  const none = h.rows.length || h.failure || ((h.only || capped) && h.next) ? ''
    : h.only && h.total > 0 ? (h.q || h.day ? 'Mandu has not stepped in in any session' + (h.q ? ' that matches \u201c' + h.q + '\u201d' : '') + onDay + '.' : '')
    : h.day && h.all > 0 ? 'No session' + (h.q ? ' matches \u201c' + h.q + '\u201d' : '') + onDay + '.'
    : h.q && h.all > 0 ? 'No session matches \u201c' + h.q + '\u201d.' : '';
  const from = h.day ? 'from ' + historyDayWords(h.day) + ' back' : '';
  const shown = !counted ? ''
    : h.only ? 'Showing the sessions where Mandu stepped in' + (h.q ? ' that match \u201c' + h.q + '\u201d' : '')
    : capped ? h.total + ' in the newest ' + h.through + ' of ' + n(h.of || h.all, 'session', 'sessions')
    : h.q ? h.total + ' of ' + n(h.all, 'session', 'sessions') : '';
  findCount(document.getElementById('history-count'), !counted ? '' : shown ? shown + (from ? ', ' + from : '') : from.charAt(0).toUpperCase() + from.slice(1), none);
  // With the switch: Show more goes on while sessions are left to look
  // through, and says how far it looked, since how many more it will keep
  // is not known (none yet: "has not stepped in in the newest 200").
  // A search that stopped short says the same, of every session it could
  // look through.
  const among = capped ? h.of || h.all : h.total;
  const lookedLine = () => moreLine('history-more', h.failure ? cannotCheck('Could not read more of the history.', h.failure, false)
    : [h.rows.length ? 'Looked through ' + h.through + ' of ' + n(among, 'session', 'sessions') + '.'
      : capped ? 'None of the newest ' + h.through + ' of ' + n(among, 'session', 'sessions') + ' matches \u201c' + h.q + '\u201d.'
      : 'Mandu has not stepped in in the newest ' + h.through + ' of ' + n(h.total, 'session', 'sessions') + '.'], () => loadHistory(true));
  if (!h.rows.length && (h.only || capped) && h.next) {
    keepRows(host, [lookedLine()]);
    return true;
  }
  if (off && !never) {
    keepRows(host, [el('div', { class: 'empty' }, ...cannotCheck('', 'not-running', false, 'your sessions show here'))]);
    return true;
  }
  if (!h.rows.length && h.failure && !never) {
    keepRows(host, [el('div', { class: 'empty' }, ...cannotCheck('Could not read the history.', h.failure, false))]);
    return true;
  }
  if (!h.rows.length && h.only && h.total > 0) {
    const allBtn = el('button', { type: 'button', class: 'btn small history-all', text: 'Show every session' });
    allBtn.addEventListener('click', () => {
      setHistoryOnly(false);
      document.getElementById('history-only').focus();
    });
    keepRows(host, [el('div', { class: 'empty' }, (none || 'Mandu has not stepped in in any session on record.') + ' ', allBtn)]);
    return true;
  }
  if (!h.rows.length && h.day && h.all > 0) {
    const newest = el('button', { type: 'button', class: 'btn small history-clear history-newest', text: 'Show the newest' });
    newest.addEventListener('click', showHistoryNewest);
    keepRows(host, [el('div', { class: 'empty' }, none + ' ', newest)]);
    return true;
  }
  if (!h.rows.length && h.q && h.all > 0) {
    const clearBtn = el('button', { type: 'button', class: 'btn small history-clear', text: 'Clear' });
    clearBtn.addEventListener('click', clearHistorySearch);
    keepRows(host, [el('div', { class: 'empty' }, none + ' ', clearBtn)]);
    return true;
  }
  if (!h.rows.length) {
    // Home's *Get started* step, in the list's words.
    // The commands are the agents you use (`start`, §4.25ae).
    keepRows(host, [el('div', { class: 'empty' }, 'No session has been recorded yet. Start your agent through Mandu, ',
      ...startCodes(S.home), ', and it shows up here.')]);
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
  if ((h.only || capped) && h.next) {
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
/** What a row (History's, Running now's, Earlier's) can show that What
 *  the counts mean explains, in its counts line's order (rowMarks, then
 *  rowCounts): each kind of
 *  COUNT_MEANINGS with whether a row shows it. Not "N questions waiting
 *  for you" (a link that says what it is), nor the frozen levels'
 *  untrusted items (integrity is frozen; a session page's fold leaves it
 *  out too). A mark is said of one session, a count of many (its term is
 *  plural: "Each went to …"). */
const ROW_MEANINGS = [
  ['failed', (a) => !a.holds, 1],
  ['off', (a) => !!a.protectionOff, 1],
  ['less', (a) => !!a.lessProtection, 1],
  ['masked', (a) => !!(a.secrets && a.secrets.masked), 2],
  ['early', (a) => !!(a.secrets && a.secrets.early), 2],
  ['blocked', (a) => !!a.blocked, 2],
  ['sent', (a) => !!a.sent, 2],
];
/** A *What the counts mean* fold over rows (dashboard.md §4.25 *What the
 *  counts mean*: History's under its search, §4.25ae; Home's under its
 *  lists, renderHomeMeanings): a term and its meaning for each kind of
 *  count or mark a drawn row shows. Hidden when none does. The same kinds
 *  as drawn leave it alone (no flicker, the focus kept); new ones draw its
 *  list again, the fold open or closed as you left it. */
function drawRowMeanings(fold, rows) {
  if (!fold) return;
  const kinds = ROW_MEANINGS.filter(([, shows]) => rows.some(shows));
  const key = kinds.map(([kind]) => kind).join(' ');
  if (fold.dataset.kinds === key) return;
  fold.dataset.kinds = key;
  const list = fold.querySelector('dl');
  clear(list);
  for (const [kind, , k] of kinds) {
    const m = COUNT_MEANINGS[kind];
    list.append(el('dt', { text: m.mark || m.term }), el('dd', { text: m.means(k) }));
  }
  fold.hidden = kinds.length === 0;
}
/** What a History row is drawn from: a running one as Running now's
 *  (liveDrawnFrom, its last step moved in place by moveLastSteps), an ended
 *  one with the moment it ended. */
function historyDrawnFrom(a) {
  return a.state !== 'idle' ? liveDrawnFrom(a) : rowDrawnFrom(a, 'lastAt');
}
/** A History row for keepRows: Home's row (agentRow), its moment
 *  `moment`, when the session started if it runs, with its last step as
 *  Running now names it (liveWhen), else when it ended. */
function historyRow(a, moment) {
  return keptRow(a, moment, () => {
    const what = promptLine(a, 'No prompt reached the AI');
    // A question it raised still waits in Approvals, in Home's words (the
    // row keeps its prompt, as Home's do), and in its Home row's order: a
    // running agent leads with it after its marks, as Running now does, and
    // has Running now's dot; an ended one says it last, as Earlier does
    // (§4.25ae *History says what waits for you*).
    const running = a.state !== 'idle';
    const bits = rowMarks(a);
    if (a.waiting && running) bits.push(waitingLink(a));
    bits.push(...rowCounts(a));
    // Ended, a change to a secret file Mandu did not apply, as Earlier says.
    const lost = notAppliedLink(a);
    if (lost) bits.push(lost);
    if (a.waiting && !running) bits.push(waitingLink(a));
    const row = agentRow(a, el('span', { class: 'dot' + (!a.holds ? ' bad' : a.state === 'waiting' || rowWarn(a) ? ' warn' : running ? ' ok' : '') }), what,
      countsLine('dim', bits),
      running ? liveWhen(a, 'running now, started') : whenLine('agent-ended', 'ended', a.lastAt));
    // Found by a secret or a host, not by its own words: why it is here.
    const found = foundLine(a.found, a.id);
    if (found) row.querySelector('.agent-what').append(found);
    return row;
  }, historyDrawnFrom(a));
}
/** The most names a History row's Found line says before "and N more". */
const FOUND_SHOWN = 3;
/** Where a Found line's name opens its session (`?go=`, AGENT_GO): a
 *  secret at Your secrets, a send at its sent steps, a blocked send at its
 *  blocked steps (dashboard.md §4.25ae, #301). */
const FOUND_GO = ['secrets', 'sent', 'blocked'];
/** "Found here: STRIPE_KEY in ~/proj/.env and a blocked send to
 *  pastebin.com" under a History row a search found by its secrets or
 *  hosts, not by its own words (`found`, dashboard.md §4.25ae *By a secret
 *  or a host*): at most FOUND_SHOWN names, then "and N more" (plain words).
 *  Each name `{ name, go }` is a link into session `id` at the place it
 *  came up (`?go=`, FOUND_GO), a tab stop of its own inside the row, as
 *  waitingLink's is; a plain string (an older server) or an unknown `go`
 *  is drawn as words. Names and hosts only, as the server sends them. null
 *  without any. */
function foundLine(found, id) {
  const names = (Array.isArray(found) ? found : []).map((x) => (typeof x === 'string' ? { name: x, go: null }
    : x && typeof x === 'object' && typeof x.name === 'string' ? { name: x.name, go: FOUND_GO.includes(x.go) ? x.go : null } : null))
    .filter((x) => x && x.name);
  if (!names.length) return null;
  const shown = names.slice(0, FOUND_SHOWN);
  const more = names.length - shown.length;
  const line = el('div', { class: 'dim history-found' }, 'Found here: ');
  shown.forEach((x, i) => {
    if (i > 0) line.append(i === shown.length - 1 && !more ? ' and ' : ', ');
    line.append(x.go && id
      ? el('a', { class: 'history-found-link', href: routeHref('agent', id, null, x.go), 'data-page-link': 'agent', 'data-session': id, 'data-land': x.go, text: x.name })
      : x.name);
  });
  if (more) line.append(' and ' + more + ' more');
  return line;
}

// ── The day a History row is on (dashboard.md §4.25ae *Sessions sit under their day*) ──
/** A heading of History for keepRows: the local day `key` ("2026-07-10",
 *  localDay), an h2 under the page h1 so a screen reader can go from day
 *  to day, slim in the list (app.css `.history-day`). Its key is the day
 *  (with `nth` past its first heading, when a running row started on a day
 *  listed again further down), so a poll leaves a heading already there in
 *  place as it does a row; its words are said again by refreshWhen.
 *  Approvals › Answered earlier draws the same under its section's h2
 *  (`tag` 'h3', drawAnswered). */
function historyDay(key, nth, tag = 'h2') {
  const id = 'day:' + key + (nth > 1 ? ':' + nth : '');
  return { key: id, from: id, make: () => el(tag, { class: 'history-day', 'data-session': id }, el('time', { datetime: key, text: dayWords(key) })) };
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
    document.getElementById('home-data-broken').hidden = true;
    list.append(el('div', { class: 'empty' }, 'The list could not be loaded. Run ', runCode('mandu paths'), ' in a terminal to see it.'));
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
      runCode('mandu paths'), ' in a terminal for the command that makes them yours only.');
  }
  // A broken link says what it means and what to do in words, as `mandu
  // paths` does under its table, not only in a hover title: every row the
  // list shows, wherever it is (§4.25q). Each badge is described by it.
  const broken = shown.filter((l) => l.exists && l.brokenLink).length;
  const brokenNote = document.getElementById('home-data-broken');
  brokenNote.hidden = broken === 0;
  clear(brokenNote);
  if (broken) {
    brokenNote.append((broken === 1 ? '1 place here is a link' : broken + ' places here are links')
      + ' to something that is not there, so Mandu cannot use ' + (broken === 1 ? 'it' : 'them')
      + ' until the link\'s target is back (a disk not mounted?) or the link is removed. Run ',
      runCode('mandu doctor'), ' in a terminal: it names each one.');
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
  else if (l.brokenLink) mark = el('span', { class: 'tag broken-link', text: 'broken link', 'aria-describedby': 'home-data-broken' });
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
  // So does a mark that comes or goes on an ended question, whose card is
  // full only while marked (askFolds); a key of its own, which no draw of
  // Answered earlier alone takes.
  // The heading counts every question in the list, those from sessions that
  // have ended too; none when none waits or the queue was not read (§4.25
  // *Waiting for your answer counts its questions*). Before the return
  // below, so a poll that leaves the cards as drawn still sets it; written
  // only when it changed.
  const count = document.getElementById('approvals-waiting-count');
  const counted = home && home.waitingKnown && home.waiting.length ? '(' + home.waiting.length + ')' : '';
  if (count && count.textContent !== counted) count.textContent = counted;
  const markMoved = !sameAsDrawn('approvals-marked', markedEnded(home));
  // A phone draws its cards short (askFolds): drawn again when it flips.
  const formMoved = !sameAsDrawn('approvals-phone', onPhone());
  if (sameAsDrawn('approvals', approvalsKey(home)) && !markMoved && !formMoved) return;
  const waiting = document.getElementById('approvals-waiting');
  renderAsks(waiting, home, true, S.proposals.length > 0, 'grouped');
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
  S.changes = { want: CHANGES_PAGE, last: null, failure: null, out: 0, read: false, sought: null, limit: 0 };
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
  const a = S.answered;
  // A search (§4.25 *Finding an answer*) lists what its reads found, never
  // the newest 20 of Home: the rows of the last search until those of the
  // new one come (`q` the search they answer), or none yet (`pending`).
  // So does a day (*Go to a day on Answered earlier*, `day`), alone or
  // with a search.
  if (answeredFinding()) {
    if (!a || !answeredFound(a)) return { rows: [], next: null, total: 0, failure: null, q: S.answeredQ, day: S.answeredDay, all: homeTotal, pending: true };
    return { rows: a.rows, next: a.next, total: a.total, failure: a.failure, q: a.q, day: a.day || '', all: a.all };
  }
  const first = { rows, next: homeTotal > rows.length && rows.length ? rows[rows.length - 1].id : null };
  if (!a || answeredFound(a)) return { ...first, total: homeTotal, failure: null };
  const kept = historyFollowed(a, first);
  return { ...kept, total: Math.max(homeTotal, a.total || 0, kept.rows.length), failure: a.failure };
}

/** What the two lists of questions on Approvals are drawn from (sameAsDrawn). A
 *  rule change that comes or goes while no question waits changes the line
 *  of the list ("No question …" / "Nothing …"), so it is part of the key. */
function approvalsKey(home) {
  if (!home || !home.waitingKnown) return ['failed', S.homeFailure, offKey()];
  return [home.waiting, answeredKey(answeredList(home)), !home.waiting.length && S.proposals.length > 0];
}
/** What Answered earlier is drawn from (sameAsDrawn). */
function answeredKey(list) {
  return [list.rows, list.total, list.next, list.failure, list.q || '', list.day || '', list.all || 0, !!list.pending];
}
/** Whether Answered earlier is found by a search or a day (§4.25 *Finding
 *  an answer*, *Go to a day on Answered earlier*): it then lists what the
 *  reads of its own found, never the newest 20 of Home. */
function answeredFinding() {
  return !!(S.answeredQ || S.answeredDay);
}
/** Whether the read `a` of Answered earlier was found by a search or a day. */
function answeredFound(a) {
  return !!(a.q || a.day);
}
/** Whether the read `a` answers the search and the day the page holds. */
function answeredFoundNow(a) {
  return !!a && (a.q || '') === S.answeredQ && (a.day || '') === S.answeredDay;
}

/** Draws Answered earlier when what it shows changed (`force`: always, as
 *  a Show more that answered draws). Whether it drew. */
function renderAnswered(home, force) {
  const host = document.getElementById('approvals-answered');
  const list = home && home.waitingKnown ? answeredList(home) : null;
  const same = sameAsDrawn('answered', list ? answeredKey(list) : ['failed', S.homeFailure, offKey()]);
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
  // Not while the first read of a search or a day is out: the rows drawn
  // are of another.
  if (answeredFinding() && !answeredFoundNow(S.answered)) return;
  const host = document.getElementById('approvals-answered');
  const drawnNow = answeredList(home);
  const a = S.answered || (S.answered = { q: '', day: '', rows: [], next: null, total: 0, all: 0, failure: null, out: 0, homeAt: S.homeAsked });
  Object.assign(a, { rows: drawnNow.rows.slice(), next: drawnNow.next, total: drawnNow.total });
  const had = new Set(a.rows.map((x) => x.id));
  const asked = ANSWERED_READS.ask();
  let r = null;
  let failure = null;
  a.out++;
  try { r = await apiGet('home/answered?after=' + enc(a.next || '') + '&limit=' + ANSWERED_PAGE + answeredFind(a.q, a.day)); } catch (err) { failure = readFailure(err); }
  a.out--;
  a.homeAt = S.homeAsked;
  if (S.answered !== a || !ANSWERED_READS.take(asked)) return;
  let first = null;
  if (r) {
    const fresh = (r.rows || []).filter((x) => !had.has(x.id));
    a.rows.push(...fresh);
    a.next = r.next || null;
    a.total = r.total || 0;
    a.all = historyAll(r);
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
  // Nor while the first read of a search or a day is out (readAnswersFound):
  // it would read the one before it, and its answer, asked later, would win.
  if (S.page !== 'approvals' || !a || a.out || a.homeAt >= homeAsked || !answeredFoundNow(a)) return;
  const asked = ANSWERED_READS.ask();
  let r = null;
  a.out++;
  try { r = await apiGet('home/answered?limit=' + Math.min(Math.max(a.rows.length, ANSWERED_PAGE), ANSWERED_PAGE_MAX) + answeredFind(a.q, a.day)); } catch { r = null; }
  a.out--;
  a.homeAt = S.homeAsked;
  if (S.page !== 'approvals' || S.answered !== a || !ANSWERED_READS.take(asked) || !r) return;
  Object.assign(a, historyFollowed(a, r), { total: r.total || 0, all: historyAll(r), failure: null });
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
      S.answered = { q: '', day: '', rows: kept, next: more ? kept[kept.length - 1].id : null, total: r.total || 0, all: r.total || 0, failure: null, out: 0, homeAt: S.homeAsked };
      if (S.home) renderAnswered(S.home, true);
    }
    if (S.approvalsAsk === id) markApprovalsAsk();
  })();
  return true;
}

// ── Finding an answer (dashboard.md §4.25 *Finding an answer*) ─────────────
let answeredSearchTimer = 0;
/** The search `q` and the day `day` of Answered earlier as the end of a
 *  read (`&q=…&before=<ms>`, the moment the next day starts, historyDayEnd),
 *  or ''. */
function answeredFind(q, day) {
  return (q ? '&q=' + enc(q) : '') + (day ? '&before=' + historyDayEnd(day) : '');
}
/** The words in the box, read: once the typing stops (HISTORY_SEARCH_MS), or at
 *  once (`now`, Enter, Escape or Clear), as the search of History. A search that
 *  changed lists only its matches, newest 20 first, and writes itself into
 *  the address (replaced, not pushed); it drops an answer the address
 *  opened (`/approvals/<id>`) with its mark. Only the list is drawn again,
 *  so the focus stays in the box. */
function findAnswers(text, now) {
  clearTimeout(answeredSearchTimer);
  const run = () => {
    if (S.page !== 'approvals') return;
    const q = historyQuery(text);
    // The same search again reads again only when its read failed.
    if (q === S.answeredQ && !(q && answeredFoundNow(S.answered) && S.answered.failure && !S.answered.rows.length)) return;
    S.answeredQ = q;
    if (S.approvalsAsk) {
      S.approvalsAsk = null;
      markApprovalsAsk();
    }
    const href = stateHref();
    if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
    if (answeredFinding()) readAnswersFound();
    else S.answered = null;
    if (S.home) renderAnswered(S.home);
  };
  if (now) run();
  else answeredSearchTimer = setTimeout(run, HISTORY_SEARCH_MS);
}
/** The search the address names is the one Answered earlier lists: read
 *  when it is not (a reload, a typed address, Back to another search);
 *  none, and the rows drawn are those of a search: back to the newest. */
function answeredSearchNow() {
  const a = S.answered;
  if (answeredFinding()) {
    if (!answeredFoundNow(a)) readAnswersFound();
  } else if (a && answeredFound(a)) S.answered = null;
  if (S.home) renderAnswered(S.home);
}
/** The first ANSWERED_PAGE answers a search or a day finds (GET
 *  /api/home/answered?q=&before=); Show more and the poll then go on as
 *  without one. A read that fails says why where the rows go. */
async function readAnswersFound() {
  const q = S.answeredQ;
  const day = S.answeredDay;
  const asked = ANSWERED_READS.ask();
  let r = null;
  let failure = null;
  try { r = await apiGet('home/answered?limit=' + ANSWERED_PAGE + answeredFind(q, day)); } catch (err) { failure = readFailure(err); }
  if (S.page !== 'approvals' || S.answeredQ !== q || S.answeredDay !== day || !ANSWERED_READS.take(asked)) return;
  S.answered = r
    ? { q, day, rows: Array.isArray(r.rows) ? r.rows : [], next: r.next || null, total: r.total || 0, all: historyAll(r), failure: null, out: 0, homeAt: S.homeAsked }
    : { q, day, rows: [], next: null, total: 0, all: 0, failure, out: 0, homeAt: S.homeAsked };
  if (S.home) renderAnswered(S.home, true);
}
/** Clear: the box empty, the newest answers listed again, the box focused. */
function clearAnsweredSearch() {
  const box = document.getElementById('answered-q');
  box.value = '';
  findAnswers('', true);
  box.focus();
}
function wireAnsweredSearch() {
  const box = document.getElementById('answered-q');
  box.addEventListener('input', () => findAnswers(box.value, false));
  document.getElementById('answered-search').addEventListener('submit', (e) => {
    e.preventDefault();
    findAnswers(box.value, true);
  });
  // Escape empties the box (a plain one, and only with words in it: an
  // empty box leaves Escape to whatever else takes it), as on Rules.
  box.addEventListener('keydown', (e) => {
    if (!plainEscape(e) || !box.value) return;
    e.preventDefault();
    clearAnsweredSearch();
  });
  // A date box fires `change` once a whole day is chosen or it is cleared.
  const day = document.getElementById('answered-day');
  day.addEventListener('change', () => setAnsweredDay(day.value));
  document.getElementById('answered-newest').addEventListener('click', showAnsweredNewest);
}

// ── Go to a day on Answered earlier (dashboard.md §4.25) ────────────────────
/** The box as the day of Approvals says it: its value, today as its latest
 *  day, and Show the newest beside it while a day is set (as History has,
 *  showHistoryDay). */
function showAnsweredDay() {
  const box = document.getElementById('answered-day');
  if (box.value !== S.answeredDay) box.value = S.answeredDay;
  box.max = localDay(Date.now()).key;
  document.getElementById('answered-newest').hidden = !S.answeredDay;
}
/** A day chosen in the box, or '' (cleared, or Show the newest): Answered
 *  earlier starts over from it, with the search it has, and the address
 *  says so (replaced, not pushed); it drops an answer the address opened,
 *  as a search does. Only the list is drawn again. */
function setAnsweredDay(day) {
  if (S.page !== 'approvals') return;
  const next = historyDayParam(day);
  if (next === S.answeredDay && (!answeredFinding() || answeredFoundNow(S.answered))) return;
  S.answeredDay = next;
  showAnsweredDay();
  if (S.approvalsAsk) {
    S.approvalsAsk = null;
    markApprovalsAsk();
  }
  const href = stateHref();
  if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
  if (answeredFinding()) readAnswersFound();
  else S.answered = null;
  if (S.home) renderAnswered(S.home);
}
/** Show the newest: no day, the answers from the newest (with the search,
 *  if any), the box focused. */
function showAnsweredNewest() {
  setAnsweredDay('');
  document.getElementById('answered-day').focus();
}
/** The box and its count line (§4.25 *Finding an answer*): hidden while
 *  there is no answer to find and no search (the box keeps a focus it
 *  holds); "3 of 63 answers match" while a search finds some, and the
 *  "No answer matches …" of the list to a screen reader while it finds
 *  none (findCount). */
function drawAnsweredSearch(list) {
  const form = document.getElementById('answered-search');
  const count = document.getElementById('answered-count');
  if (!list) return;
  if (!list.failure && !list.pending) form.hidden = !list.q && !list.day && list.total === 0 && !form.contains(document.activeElement);
  // A day (§4.25 *Go to a day on Answered earlier*) says where the list
  // starts, "From Tuesday, Oct 20 back", after the count of a search.
  const counted = (!!list.q || !!list.day) && list.rows.length > 0;
  const from = list.day ? 'from ' + historyDayWords(list.day) + ' back' : '';
  const found = list.q ? list.total + ' of ' + n(Math.max(list.all || 0, list.total), 'answer', 'answers') + (list.total === 1 ? ' matches' : ' match') : '';
  findCount(count, !counted ? '' : found ? found + (from ? ', ' + from : '') : from.charAt(0).toUpperCase() + from.slice(1),
    answersNoneShown(list) ? answersNone(list.q, list.day) : '');
}
/** Whether Answered earlier says that its search or its day finds none
 *  (a day before every answer, while some exist). */
function answersNoneShown(list) {
  return !list.rows.length && !list.failure && !list.pending && (!!list.q || (!!list.day && (list.all || 0) > 0));
}
/** What Answered earlier says when a search or a day finds none. */
function answersNone(q, day) {
  const onDay = day ? ' on or before ' + historyDayWords(day) : '';
  return q ? 'No answer matches \u201c' + q + '\u201d' + onDay + '.' : 'You answered nothing' + onDay + '.';
}
/** The status line of a search (role="status"; §4.25ae *Finding a session*,
 *  §4.25 *Finding an answer*, *Finding a rule change*, §4.25ai *Find one*
 *  on the Scan page): `count` while the
 *  search finds some; while it finds none, `none`, the sentence the list
 *  shows (without its Clear), for a screen reader only: `.sr-only` and not
 *  hidden, so its change is announced (a `hidden` that flips with the text
 *  may not be). Neither: emptied and hidden. Written only when its words
 *  change, so a redraw that finds none again says nothing again. */
function findCount(line, count, none) {
  const text = count || none || '';
  if (line.textContent !== text) line.textContent = text;
  line.classList.toggle('sr-only', !count && !!none);
  line.hidden = !text;
}

/** Approvals › Answered earlier (`list`: as answeredList gives it). The state of each
 *  row is its outcome, so the words of a refused Block instead go once it
 *  was answered otherwise. More than drawn: "Showing 20 of 63 answers."
 *  and Show more (moreAnswered). */
function drawAnswered(host, home, list) {
  clear(host);
  drawAnsweredSearch(list);
  if (!home || !home.waitingKnown || !list) {
    // No link: Waiting for your answer above has it. Mandu not running at
    // all: that, not a fault (offCause).
    host.append(el('div', { class: 'empty' }, ...cannotCheck('Could not check your earlier answers.', home ? offCause(null) : S.homeFailure, false, 'your earlier answers show here')));
    return;
  }
  if (list.pending) {
    host.append(el('div', { class: 'empty', text: 'Finding your answers\u2026' }));
    return;
  }
  if (!list.rows.length && (list.q || list.day) && (list.failure || answersNoneShown(list))) {
    // A search that found none, or whose read failed, says so, with Clear;
    // a day, with Show the newest (as on History, §4.25ae *Go to a day*).
    const btn = list.day
      ? el('button', { type: 'button', class: 'btn small history-clear history-newest', text: 'Show the newest' })
      : el('button', { type: 'button', class: 'btn small history-clear', text: 'Clear' });
    btn.addEventListener('click', list.day ? showAnsweredNewest : clearAnsweredSearch);
    host.append(el('div', { class: 'empty' }, ...(list.failure
      ? [...cannotCheck('Could not find your answers.', list.failure, false), ' ']
      : [answersNone(list.q, list.day) + ' ']), btn));
    return;
  }
  if (!list.rows.length) {
    host.append(el('div', { class: 'empty', text: 'You have not answered anything yet.' }));
    return;
  }
  // Each day the answers are on gets History's heading before its first row
  // (historyDay, an h3 under the section's h2; §4.34 *Answers sit under
  // their day*): the local day it was answered. All the rows read are drawn
  // together, so a Show more that continues the last day adds no heading.
  // A row with no time starts no day. A heading has no data-id: the lists
  // of cards (drawnCards) and the mark (markApprovalsAsk) pass it by.
  let lastDay = null;
  for (const a of list.rows) {
    if (Number.isFinite(a.decidedAt)) {
      const key = localDay(a.decidedAt).key;
      if (key !== lastDay) host.append(historyDay(key, 1, 'h3').make());
      lastDay = key;
    }
    const row = el('div', { class: 'row answered', 'data-id': a.id, 'data-state': a.outcome });
    // Its names are kept whole, as on the card it answered.
    const said = keepNamesWhole(sentenceNode(a.sentence, 'answered-sentence'));
    nameBy(row, said);
    // A standing answer (Always allowed, Allowed for this session, Blocked)
    // is one Rules keeps: its line links the row there (§4.25 *A remembered
    // answer opens where Rules keeps it*).
    const allowed = a.outcome === 'allowed' || a.outcome === 'allowed-session';
    const kept = !a.staleNote && (allowed || a.outcome === 'blocked');
    const what = answeredWhat(said, a.decidedAt, kept ? { ...a, kept: true } : a);
    // An answer that applies to nothing any more says why, and offers no
    // change (dashboard.md §4.34 "Answers that no longer apply").
    if (a.staleNote) what.append(el('div', { class: 'note answered-stale', text: a.staleNote }));
    row.append(what);
    const out = el('div', { class: 'outcome' });
    if (a.staleNote) { /* no mark: it decides nothing */ } else if (a.outcome === 'blocked') out.append(svg(ICON.x, 16));
    else if (allowed) out.append(svg(ICON.check, 16));
    out.classList.add(a.staleNote ? 'dim' : a.outcome === 'blocked' ? 'bad' : allowed ? 'ok' : 'dim');
    out.append(a.staleNote ? 'No longer applies' : answerLabel(a.outcome) || 'Allowed once');
    if (a.staleNote) out.title = answerLabel(a.outcome) || '';
    row.append(out);
    const reversal = (a.actions || [])[0];
    if (reversal) {
      // A session's answer to a held message flips as itself (§4.34). The
      // allow names the scope the arbiter keeps its …/approve as (§4.25
      // *The allow that reverses a Block names its scope*): this session on
      // a program's send keyed to one, once on one keyed to none and on one
      // run of a program, else a standing allow, the card's Always allow.
      // The server's label (the developer view's words) is never drawn here.
      const message = /^(sent|masked)/.test(a.outcome);
      const text = message ? (reversal.approve ? 'Send as written instead' : 'Send masked instead') : reversal.approve ? ALLOW_INSTEAD[a.allowKeptAs] || 'Always allow instead' : 'Block instead';
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
      : ['Showing ' + shown + ' of ' + n(Math.max(list.total, shown), 'answer', 'answers') + (list.q ? ' that match' : '') + (list.day ? ' from ' + historyDayWords(list.day) + ' back' : '') + '.'], moreAnswered));
  }
}

/** The reversal of a Block by what its allow is kept as (home.ts
 *  `HomeAnswered.allowKeptAs`); absent: 'Always allow instead'. */
const ALLOW_INSTEAD = { session: 'Allow this session instead', once: 'Allow once instead' };

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
  // A program's send allowed for its session (home.ts answeredOutcome).
  if (outcome === 'allowed-session') return 'Allowed for this session';
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
 *  (`asked.about`). No session recorded: no link. A standing answer
 *  (`asked.kept`) ends the line with Kept in Rules (keptLink). */
function answeredWhat(words, ms, asked) {
  const what = el('div', { class: 'answered-what' }, words);
  const when = whenNode(ms);
  const sessions = asked && Array.isArray(asked.sessions) ? asked.sessions : [];
  const kept = !!asked && asked.kept === true && typeof asked.id === 'string' && asked.id !== '';
  if (!when && !sessions.length && !kept) return what;
  // The folder of the agent that made a rule change (`asked.from`, changeFrom).
  const line = el('div', { class: 'dim answered-when' }, when, when && asked && asked.from ? asked.from : null);
  if (sessions.length) {
    if (when) line.append('. ');
    line.append(askLink(sessions[sessions.length - 1], asked.id, undefined, asked.about));
    if (sessions.length > 1) line.append(' (asked in ' + sessions.length + ' sessions, this shows the latest)');
  }
  if (kept) {
    if (when || sessions.length) line.append('. ');
    line.append(keptLink(asked.id));
  }
  what.append(line);
  return what;
}

/** "Kept in Rules" (dashboard.md §4.25 *A remembered answer opens where
 *  Rules keeps it*): Rules with the row of this answer open (openAnswerRule),
 *  where Remove forgets it. Its address names the row (`/rules#answer-<id>`),
 *  so a modifier click is left to the browser: a new tab at the same place. */
function keptLink(id) {
  return answerRuleLink(id, { class: 'kept-link', text: 'Kept in Rules' });
}
/** A link to the row of the answer `id` under Your rules (openAnswerRule),
 *  `attrs` its class and text; a modifier click is the browser's. */
function answerRuleLink(id, attrs, ...kids) {
  return el('a', { ...attrs, href: routeHref('rules') + '#answer-' + enc(id), onclick: (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button > 0) return;
    e.preventDefault();
    openAnswerRule(id);
  } }, ...kids);
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
  // An ended question's card is short unless the page was opened for it
  // (askFolds): drawn again when the mark comes or goes (renderApprovals).
  if (S.home) renderApprovals(S.home);
  // A page switch does not rebuild the cards, so an earlier visit's mark
  // would outlive it: clear, then mark afresh.
  for (const x of document.querySelectorAll('#page-approvals .focus')) x.classList.remove('focus');
  // Compared as values, never spliced into a selector: ids are server data.
  const find = (sel) => [...document.querySelectorAll(sel)].find((x) => x.dataset.id === id) || null;
  // Or the waiting rule change a notification opened it for (§4.25
  // *Notifications*), drawn whatever the answer about the asks.
  const proposal = id ? find('#approvals-proposals .proposal') : null;
  // Or a change made: its Rule changes row, by its own id or by that of the
  // request it answered (§4.25 *Details*).
  const change = id && !proposal ? ruleChangeRow(id) : null;
  const ruleChange = !!id && RULE_CHANGE_ID.test(id);
  // Nothing is said before the list that would hold it is read.
  const known = proposal || change ? true : ruleChange ? !!S.changes.read : !!(id && S.home && S.home.waitingKnown);
  if (!known) { note.hidden = true; return; }
  const card = proposal || (ruleChange ? null : find('#approvals-waiting .ask'));
  const row = card ? null : change || (ruleChange ? null : find('#approvals-answered .row.answered'));
  // An answer older than the rows drawn is read, then marked in place
  // (seekAnswered): never "no longer waiting" while it may be there.
  // So is a rule change older than Rule changes draws (seekChanges).
  const seeking = !card && !row && (ruleChange ? seekChanges(id) : seekAnswered(id, S.home));
  const target = card || row;
  if (target) target.classList.add('focus');
  const words = card || seeking || (change && change.dataset.id === id) ? ''
    : change ? 'That rule change was already answered. The change it made is marked below, under Rule changes.'
    : ruleChange ? ruleChangeGone(id)
    : row ? 'That question was already answered. Its answer is marked below, under Answered earlier.'
    : 'That question is no longer waiting for you.';
  note.hidden = !words;
  note.textContent = words;
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

/** The policy server's ids of a rule change: a request (`pp-…`) or a change
 *  made (`pc-…`); a question's id is neither. */
const RULE_CHANGE_ID = /^p[pc]-/;

/** Approvals is open for a rule change (a link to `/approvals/<pp-…|pc-…>`),
 *  which Rule changes may hold; a question is marked in its own lists. */
function linksRuleChange() {
  return typeof S.approvalsAsk === 'string' && RULE_CHANGE_ID.test(S.approvalsAsk);
}

/** The Rule changes row of the change `id`, or of the change the request
 *  `id` made once approved; null when neither is drawn. Compared as values. */
function ruleChangeRow(id) {
  const rows = [...document.querySelectorAll('#approvals-rule-history .row')];
  return rows.find((x) => x.dataset.id === id) || rows.find((x) => x.dataset.proposal === id) || null;
}

/** The note for a rule change that is neither waiting nor drawn under Rule
 *  changes. The changes could not be read: it cannot be shown, which says
 *  nothing of whether it is there. A request, with every change listed: it
 *  changed nothing (declined, or asked again in new words). Otherwise it may
 *  be past the rows drawn, which Show more reaches. */
function ruleChangeGone(id) {
  const st = S.changes;
  if (!st.last && st.failure && offCause(st.failure) === 'not-running') return 'Mandu is not running now, so this rule change cannot be shown. It is still kept, and shows here once Mandu starts with your first agent: ' + startWords(S.home) + '.';
  if (!st.last && st.failure) return 'Rule changes could not be read just now, so this change cannot be shown. It is still kept; try again in a moment.';
  const all = st.last && Array.isArray(st.last.changes) ? st.last.changes : null;
  const more = !!all && all.length > st.want;
  if (id.startsWith('pp-') && all && !more) return 'That rule change is no longer waiting, and it changed none of your rules.';
  return 'That rule change is not among the changes listed.' + (more ? ' Show more, under Rule changes, reaches older ones.' : '');
}

/** `/approvals/<pc-…|pp-…>` names a rule change past the rows drawn (a
 *  rule's origin line links its newest change, §4.25i): one read of the
 *  changes (up to CHANGES_MAX), then Rule changes draws down to the page
 *  that holds it, so it is marked in place, as seekAnswered does for an
 *  answer. Counted as a read out (`out`), so the poll does not read
 *  meanwhile and draw the newest 20 back over it. Whether that read is out
 *  (the page says nothing of the change yet); false once it answered, or
 *  when no more changes exist to read. */
function seekChanges(id) {
  const st = S.changes;
  const was = st.sought;
  if (was && was.id === id) return !was.done;
  const all = st.last && Array.isArray(st.last.changes) ? st.last.changes : null;
  if (!all || all.length <= st.want) return false;
  const sought = st.sought = { id, done: false };
  const block = document.getElementById('approvals-rule-history-block');
  const host = document.getElementById('approvals-rule-history');
  (async () => {
    const asked = CHANGE_READS.ask();
    st.out = (st.out || 0) + 1;
    const got = await apiGetControl('policy/changes?limit=' + CHANGES_MAX).catch(() => null);
    st.out--;
    sought.done = true;
    if (S.changes !== st || st.sought !== sought) return;
    const r = got && got.ok && got.data && Array.isArray(got.data.changes) ? got.data : null;
    const at = r ? r.changes.findIndex((x) => x.id === id || x.proposalId === id) : -1;
    // An Undo answered meanwhile makes this read older than the list: the
    // note then says what it says today.
    if (at >= 0 && CHANGE_READS.take(asked)) {
      const want = Math.max(st.want, Math.ceil((at + 1) / CHANGES_PAGE) * CHANGES_PAGE);
      // Cut as the poll's read of `want` would be (one more than drawn), so
      // its next read is the same, and draws nothing again.
      Object.assign(st, { want, last: { ...r, changes: r.changes.slice(0, want + 1) }, failure: null });
      sameAsDrawn('rule-history', [st.last, st.want, st.failure]);
      drawRuleHistory(false, r, [], block, host);
      return;
    }
    if (S.approvalsAsk === id) markApprovalsAsk();
  })();
  return true;
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

/** Home under its waiting cards: how many rule changes wait in Approvals,
 *  and who asked for them. When one session asked for them all and Home
 *  knows its agent (proposalsAsker), the line names it and its folder, as
 *  code as in askedFrom: "1 rule change Claude Code in ~/shop asked for is
 *  in Approvals" (dashboard.md *A rule change and the agent that asked*). */
function renderHomeProposalLink() {
  const host = document.getElementById('home-waiting');
  if (!S.proposals.length) return;
  const k = S.proposals.length;
  if (!S.proposals.every(askedByAgent)) {
    host.append(proposalsLink(S.proposals, { class: 'more', text: n(k, 'rule change waits', 'rule changes wait') + ' for you in Approvals' }));
    return;
  }
  const asker = proposalsAsker(S.proposals);
  const who = !asker ? ['your agent'] : asker.cwd ? [asker.agent + ' in ', nameCode(shortPath(asker.cwd))] : [asker.agent];
  host.append(proposalsLink(S.proposals, { class: 'more' },
    n(k, 'rule change ', 'rule changes '), ...who, ' asked for ' + (k === 1 ? 'is' : 'are') + ' in Approvals'));
}

/** The agent of the session that asked for every rule change in `list`,
 *  with its folder (proposalAsker), when all of them are from your agent,
 *  one session asked them all, and Home knows the kind of its agent. Null
 *  otherwise: the words keep "your agent" (dashboard.md *A rule change and
 *  the agent that asked*). */
function proposalsAsker(list) {
  if (!list.length || !list.every(askedByAgent)) return null;
  const session = list[0].session;
  if (!list.every((p) => p.session === session)) return null;
  const asker = proposalAsker(list[0]);
  return asker && asker.agent ? asker : null;
}

/** The id of the one rule change `list` holds, or null for none or several. */
function oneProposal(list) {
  return list.length === 1 && typeof list[0].id === 'string' && list[0].id !== '' ? list[0].id : null;
}
/** A link to Approvals for the waiting rule changes `list`: with exactly one,
 *  at that change, marked (`/approvals/<id>`, markApprovalsAsk); with
 *  several, Approvals itself (dashboard.md §4.25 *Details*). */
function proposalsLink(list, attrs, ...children) {
  const one = oneProposal(list);
  return el('a', { href: routeHref('approvals', one), 'data-page-link': 'approvals', 'data-ask': one, ...attrs }, ...children);
}

/** The rows of a rule change (a request, a change made, what it would let), each
 *  file, pattern or host in it as nameCode, so a short one is kept whole as
 *  on a waiting card (dashboard.md §4.25u, *Approvals names things whole*). */
function rowList(rows, cls) {
  const ul = el('ul', { class: cls });
  for (const r of rows || []) {
    const li = el('li');
    for (const p of r) li.append(partNode(p, nameCode, (text) => document.createTextNode(text)));
    ul.append(li);
  }
  return ul;
}

/** The agent and folder of the session that asked for a rule change, from
 *  the rows of Home in the same poll (dashboard.md *A rule change and the agent
 *  that asked*): `{ agent, cwd }`, either null when unknown (an agent of
 *  no known kind keeps "Your agent"), and `ended: true` when that session
 *  has ended (sessionEnded): the card says so, and Allow tells no one to go
 *  on (*An answer says what it did*). Null for a request not from your
 *  agent, or whose session Home does not model: the card reads as the
 *  server words it. */
function proposalAsker(p) {
  if (!p.byAgent || !p.session || p.onDisk) return null;
  const asker = sessionAsker(p.session);
  if (!sessionEnded(p.session)) return asker;
  return { ...(asker || { agent: null, cwd: null }), ended: true };
}

/** Home's row for session `id`, null when Home does not list it (older than
 *  its window, or Home has not answered yet). */
function sessionRow(id) {
  if (typeof id !== 'string' || !id) return null;
  return ((S.home && S.home.agents) || []).find((a) => a && a.id === id) || null;
}

/** Whether session `id` has ended: Home lists it and it is not running
 *  (`state` idle), the rule a question's askerEnded keeps (home.ts). A
 *  session Home does not list claims nothing. */
function sessionEnded(id) {
  const row = sessionRow(id);
  return !!row && row.state === 'idle';
}

/** The agent and folder of session `id` among Home's rows (proposalAsker),
 *  null when Home does not list it (sessionRow). */
function sessionAsker(id) {
  const row = sessionRow(id);
  if (!row) return null;
  const agent = typeof row.agent === 'string' && row.agent && row.agent !== 'The agent' ? row.agent : null;
  const cwd = typeof row.cwd === 'string' && row.cwd ? row.cwd : null;
  return agent || cwd ? { agent, cwd } : null;
}

function proposalCard(p) {
  const card = el('div', { class: 'ask expanded proposal', 'data-id': p.id });
  const top = el('div', { class: 'ask-top' });
  top.append(el('div', { class: 'ask-icon' }, svg(ICON.lock)));
  const body = el('div', { class: 'ask-body' });
  // A request of your agent names the agent that asked, as the card of a
  // question does ("Claude Code wants to change a rule"); the words of the
  // server when Home does not know the session.
  // Its headline is its heading, as for a question (askCard).
  const asker = proposalAsker(p);
  const headline = el('h3', {
    class: 'ask-sentence',
    text: asker && asker.agent ? asker.agent + ' wants to change a rule' : p.headline || (p.requester || 'Your agent') + ' wants to change a rule',
  });
  body.append(headline);
  nameBy(card, headline);
  // The moment alone, with no period, as the waiting cards below (askCard);
  // no moment recorded, no words. After it, the folder of the session that
  // asked, in the words of a question card (askedFrom: "· from Claude Code in
  // ~/projects/shop").
  const when = whenNode(p.createdAt);
  const from = when && asker && asker.cwd ? askedFrom({ askerCwd: asker.cwd, askerAgent: asker.agent || 'your agent', askerSessions: 1 }) : null;
  // The session that asked has ended: the sentence of a question whose
  // asker ended (askCard), without its "Your answer counts the next time an
  // agent asks.", since an allowed change is in force for every agent and
  // nothing asks it again (dashboard.md §4.25 *An answer says what it did*).
  const ended = !!(asker && asker.ended);
  body.append(el('div', { class: 'ask-sub' }, when && p.onDisk ? 'Seen ' : null, when, from, ended && when ? '.' : null,
    ended ? el('span', { class: 'ask-ended', text: (when ? ' ' : '') + 'The agent that asked has ended, so nothing is waiting on this now.' }) : null));
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
  // A wide change says why it asks for the typed word on a line of its
  // own, above the foot, so it is read before the link and the box; the
  // foot is then that of every card: the link left, the box with the
  // answers right (dashboard.md §4.25 *The request's card*).
  if (p.overBroad) card.append(wideWhy(p.overBroadWhy, p.warnings && p.warnings.length, true));
  const foot = el('div', { class: 'proposal-foot', style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' });
  // The agent that asked, as a question card links it (dashboard.md §4.25
  // *A rule change and the agent that asked*).
  if (p.session) foot.append(askLink(p.session, null, 'margin-right:auto;font-size:14px', about));
  let hint = null;
  if (p.overBroad) {
    const box = confirmBox(allow, rowControlName('Type ALLOW to confirm this wide change', about), S.proposalTyped.get(p.id), (v) => S.proposalTyped.set(p.id, v));
    hint = box.hint;
    foot.append(box.input);
  }
  actions.append(allow, notNow);
  foot.append(actions);
  if (hint) foot.append(hint);
  card.append(foot);
  return card;
}

/** A typed word (the ALLOW in a wide change's box, the OFF of the
 *  Protection switch) counts in any case, with the spaces around it
 *  trimmed: a phone keyboard capitalises the first letter ("Allow", "Off"), and
 *  autocomplete adds a space (dashboard.md §4.25 *The typed ALLOW takes any
 *  case*, *Turning protection off asks on the page*). The word must still
 *  be typed. */
function typedWord(value, word) {
  return String(value == null ? '' : value).trim().toUpperCase() === word;
}
/** The ALLOW of a wide change. */
function typedAllow(value) {
  return typedWord(value, 'ALLOW');
}
let confirmHintSeq = 0;
/** The Type ALLOW box of a wide change, for `button` (Allow, or Describe's
 *  Apply), which it keeps off until the word is typed. It asks a phone for
 *  capitals and no corrections; Enter presses the button when it is on;
 *  while it holds a word that does not count, the hint line under the foot
 *  says so and describes the box. `value`: what was typed before (a redraw);
 *  `onType`: told each change; `busy`: true while the request of the
 *  button is out, which keeps it off whatever is typed; `ask`: another word
 *  to type (`word`) and its hint line (`hint`), as the OFF of the Protection
 *  switch. Returns the box and its hint, for the caller to place. */
function confirmBox(button, label, value, onType, busy, ask) {
  const word = (ask && ask.word) || 'ALLOW';
  const hint = el('div', { class: 'confirm-hint', id: 'confirm-hint-' + (++confirmHintSeq), text: (ask && ask.hint) || 'Type the word ALLOW to turn on ' + button.textContent + '.' });
  const input = el('input', {
    type: 'text', class: 'proposal-confirm', placeholder: 'Type ' + word + ' to confirm', 'aria-label': label,
    autocapitalize: 'characters', autocorrect: 'off', spellcheck: 'false', autocomplete: 'off',
  });
  input.value = value || '';
  const sync = () => {
    const ok = typedWord(input.value, word);
    button.disabled = !ok || (!!busy && busy());
    hint.hidden = ok || !input.value.trim();
    if (hint.hidden) input.removeAttribute('aria-describedby');
    else input.setAttribute('aria-describedby', hint.id);
  };
  sync();
  input.addEventListener('input', () => {
    if (onType) onType(input.value);
    sync();
  });
  // Enter presses the button as a click would, focus included, so what
  // follows an answer is the same; off (or busy, its POST out), nothing.
  input.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || e.isComposing) return;
    e.preventDefault();
    if (button.disabled || !typedWord(input.value, word)) return;
    button.focus();
    button.click();
  });
  return { input, hint };
}

/** The line of a wide change about its Type ALLOW field: what it opens,
 *  one sentence per wide edit as the server words it, and why it asks for
 *  the typed word (dashboard.md §4.25 *A wide change says what is open*).
 *  With a warning, the line about it, as before; an older server that sends
 *  no sentences, the old words. `own`: a line of its own above the foot (a
 *  rule change on Approvals); else in the foot before the field, which it
 *  pushes right (Describe's suggestion). */
function wideWhy(why, warned, own) {
  const line = own ? el('div', { class: 'dim wide-why' }) : el('span', { class: 'dim wide-why', style: 'margin-right:auto' });
  const list = Array.isArray(why) ? why : [];
  list.forEach((parts, i) => line.append(i ? ' ' : '', fitWords(parts)));
  const tail = warned ? 'Read the warning above before you allow this.' : list.length ? 'Type ALLOW if you mean it.' : 'This change has no limit on one side.';
  line.append((list.length ? ' ' : '') + tail);
  return line;
}

/** The line an answer to a rule change leaves where its card was
 *  (dashboard.md §4.25 *An answer says what it did*): what you chose, and
 *  about what in the words the card drew to name its buttons
 *  (changeWords: its first line as drawn, names as code, and how many
 *  more), never the reason your agent gave nor a pattern the card hid;
 *  what it did; for Allow, to tell the agent that asked (none when no
 *  agent asked, or when its session has ended) and the Undo of the change made (`/approvals/<pc-…>`, its
 *  row under Rule changes, markApprovalsAsk; an older server sends no
 *  change id, and the line has no link). Until 2026-10-25 the card just
 *  went, and the Undo sat at the bottom of the page. */
function proposalLine(p, verdict, card, changeId) {
  const asker = proposalAsker(p);
  const agent = asker && asker.agent;
  const who = p.onDisk ? 'The change to policy.yaml'
    : askedByAgent(p) ? (agent || 'Your agent') + '\'s rule change'
      : p.requester === 'You' ? 'Your rule change'
        : typeof p.requester === 'string' && p.requester ? p.requester + '\'s rule change' : 'The rule change';
  // The list the card named itself by (`about` in proposalCard).
  const rows = card.querySelector('.proposal-rows');
  const lets = card.querySelector('.proposal-let');
  const list = (rows && rows.children.length) || !lets ? rows : lets;
  const lines = list ? [...list.children].filter(lineWords) : [];
  const words = [who];
  let said = who;
  if (lines.length) {
    const more = lines.length > 1 ? ', and ' + (lines.length - 1) + ' more' : '';
    words.push(': ', ...[...lines[0].childNodes].map((x) => x.cloneNode(true)), more);
    said += ': ' + lineWords(lines[0]) + more;
  }
  if (!/[.!?]$/.test(said)) words.push('.');
  const allowed = verdict === 'approved';
  const after = allowed
    ? 'It is in force now.' + (askedByAgent(p) && !(asker && asker.ended) ? ' Tell ' + (agent || 'your agent') + ' it may go on.' : '')
    : p.onDisk ? 'Your rules stay as they are, and policy.yaml was written back to match them.' : 'Your rules stay as they are.';
  const undo = allowed ? changesLink(changeId, 'Undo it') : null;
  if (undo) undo.classList.add('answer-change');
  return { verb: { head: allowed ? 'Allowed' : 'Not now', words, after }, link: undo };
}

async function decideProposal(p, verdict, card) {
  if (S.busy.has(p.id)) return;
  S.busy.add(p.id);
  const place = answerPlace(card);
  dropAnswer(place, card);
  for (const b of card.querySelectorAll('button')) b.disabled = true;
  let d;
  try {
    const r = await apiPost('policy/proposals/' + encodeURIComponent(p.id), { verdict });
    if (!r.ok) {
      keepAnswer(place, card, refusalText(r, 'could not record your answer (' + r.status + ')'));
      return;
    }
    d = r.data || {};
    S.proposalNotice = d.refiled
      ? { id: d.refiled.id, text: 'The rules changed since ' + (askedByAgent(d.refiled) ? 'your agent asked' : 'this was asked') + '; here is the updated request.' }
      : null;
    // Answered: the request no longer waits, whatever a read asked before
    // this answer still lists (readsInOrder drops it). A poll that draws
    // before the read after this answer draws without it too.
    S.proposals = S.proposals.filter((q) => q.id !== p.id);
    PROPOSAL_READS.wrote();
  } finally {
    S.busy.delete(p.id);
  }
  // Answered here: as a question's card (decide), Approvals no longer points
  // at it, so the note never calls your own answer an earlier one.
  if (S.approvalsAsk === p.id) {
    S.approvalsAsk = null;
    if (S.page === 'approvals') history.replaceState(history.state, '', routeHref('approvals'));
  }
  // A request filed again keeps its notice above the updated card instead.
  if (!d.refiled) {
    const line = proposalLine(p, verdict, card, d.changeId);
    answerLine(place, card, p, line.verb, line.link);
    S.proposalAnswered = p;
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
  // Who asked is read from the rows of Home: a poll that brings the row of
  // the session draws the card again, with its agent and folder.
  // The line an answer left keeps the block shown (answerLine), and a
  // page left drops it, so the block hides again on coming back.
  const answered = hasAnswerLine('proposal');
  // Named by what waits; with nothing left but the line, by whose change it was.
  const named = !S.proposals.length && answered && S.proposalAnswered ? [S.proposalAnswered] : S.proposals;
  const namedAsker = proposalsAsker(named);
  // The heading counts the cards listed under it; none with only an
  // answer's line left (§4.25 *Rule changes count their cards*). Before the
  // return below, as Waiting for your answer's count, and written only when
  // it changed. Its space is the count's own, so the words alone end the
  // heading when none waits.
  const count = document.getElementById('approvals-proposals-count');
  const counted = S.proposals.length ? ' (' + S.proposals.length + ')' : '';
  if (count && count.textContent !== counted) count.textContent = counted;
  if (sameAsDrawn('proposals', [S.proposals, S.proposals.map(proposalAsker), S.proposalPatternsHidden, S.proposalNotice, answered, namedAsker])) return;
  const ids = new Set(S.proposals.map((p) => p.id));
  for (const id of S.proposalTyped.keys()) if (!ids.has(id)) S.proposalTyped.delete(id);
  const active = document.activeElement;
  const typing = active && active.classList && active.classList.contains('proposal-confirm') && host.contains(active)
    ? { id: active.closest('.proposal').dataset.id, start: active.selectionStart, end: active.selectionEnd } : null;
  clear(host);
  block.hidden = S.proposals.length === 0 && !answered;
  followSectionLinks();
  // One session of a known agent asked them all: the heading names the
  // agent, and each card keeps its folder (proposalsAsker).
  // The words in their own span: the count beside them stays.
  document.getElementById('approvals-proposals-words').textContent = !named.every(askedByAgent) ? 'Rule changes waiting for you'
    : 'Rule changes ' + (namedAsker ? namedAsker.agent : 'your agent') + ' asked for';
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
  // The poll does not read while the read of Show more is out (as on History),
  // or that of a link to an older change (seekChanges).
  if (!more && st.out) return;
  const want = more ? st.want + CHANGES_PAGE : st.want;
  // A search matches the newest CHANGES_MAX (§4.25 *Finding a rule change*):
  // its poll reads them all, and a key typed reads nothing (findChanges).
  // So does a day, cut on the page (*Go to a day on Rule changes*).
  const limit = changesFinding() ? CHANGES_MAX : Math.min(want + 1, CHANGES_MAX);
  const asked = CHANGE_READS.ask();
  if (more) st.out = (st.out || 0) + 1;
  const got = await apiGetControl('policy/changes?limit=' + limit).catch(() => null);
  if (more) st.out--;
  if (S.changes !== st) return;
  // An older read than the list knows (an Undo answered meanwhile): one of
  // the poll is dropped; one of Show more draws the list again, its button on.
  const taken = CHANGE_READS.take(asked);
  if (!taken && !more) return;
  // Read once: a link to a rule change not listed can say so (markApprovalsAsk).
  const firstRead = taken && !more && !st.read;
  if (taken && !more) st.read = true;
  const r = taken && got && got.ok ? got.data : null;
  const had = st.last && Array.isArray(st.last.changes) ? st.last.changes.slice(0, st.want).map((x) => x.id) : [];
  if (r) Object.assign(st, { want, last: r, limit, failure: null });
  else if (more && taken) st.failure = changesFailure(got);
  // A poll read that failed keeps its cause too, which Rule changes says in
  // place of its rows (§4.25 *Rule changes says when it could not be
  // read*). A dashboard whose service offers no rule changes (501) has
  // nothing to fail to read: the section stays hidden.
  else if (!more) Object.assign(st, { last: null, failure: got && got.status === 501 ? null : changesFailure(got) });
  // The same changes: the rows stay as they are, the words of an Undo too,
  // and so does a mark on one. The first read of a visit can still answer a
  // link to a change these rows do not hold (markApprovalsAsk).
  // Each row's agent and folder too: the Home poll that brings its session
  // names it (changeAsker). And the search (ruleHistoryKey).
  if (sameAsDrawn('rule-history', ruleHistoryKey()) && !more) {
    if (firstRead && linksRuleChange()) markApprovalsAsk();
    return;
  }
  drawRuleHistory(more, r, had, block, host);
}

/** Why a read of the rule changes failed, as cannotCheck says it: no
 *  answer at all, the protection service not running, no service behind the
 *  route (its 404, in the words ownRefusal has for it, never the bare
 *  status: a refresh does not help), or the status. */
function changesFailure(got) {
  if (!got || got.status === 0) return 'gone';
  if (got.data && got.data.unreachable) return 'down';
  const error = got.data && typeof got.data.error === 'string' ? got.data.error : '';
  return got.status === 404 && NOT_CONNECTED_REFUSAL.test(error) ? 'not-connected' : got.status;
}
/** The place Rule changes names while Mandu is not running (cannotCheck). */
const CHANGES_OFF = 'your rule changes show here';

/** Rule changes drawn from `S.changes` into `host`: its newest `want`, and
 *  Show more while the read held one more. `more`: drawn for Show more,
 *  whose first row not in `had` takes the focus (`r`: its read answered). */
function drawRuleHistory(more, r, had, block, host) {
  const st = S.changes;
  const q = S.changesQ;
  const day = S.changesDay;
  const finding = changesFinding();
  const place = more ? null : pollPlace(host);
  const all = st.last && Array.isArray(st.last.changes) ? st.last.changes : [];
  // Under a search, the changes it finds (§4.25 *Finding a rule change*),
  // from the day chosen back (*Go to a day on Rule changes*).
  const found = finding ? changesFound(all) : all;
  const changes = found.slice(0, st.want);
  // The last poll read failed: no rows at all (never those of the read
  // before, with live Undo buttons), one line that says why in their place.
  const unread = !st.last && !!st.failure;
  clear(host);
  // A search or a day keeps the list, and its box, whatever it finds. So
  // does a read that failed, which says so.
  block.hidden = !finding && changes.length === 0 && !unread;
  drawChangesSearch(block, all, found);
  followSectionLinks();
  if (finding && !drawChangesFound(host, changes)) {
    putBackAnswers('change', host);
    if (!more) pollRefocus(place);
    return;
  }
  // The cause in the words of Answered earlier, without the link to Settings.
  if (unread) host.append(el('div', { class: 'empty changes-unread' }, ...cannotCheck('Could not read your rule changes.', offCause(st.failure), false, CHANGES_OFF)));
  if (st.last && st.last.patternsHidden && changes.length) host.append(el('div', { class: 'empty patterns-hidden', text: PATTERNS_HIDDEN_NOTE }));
  // Each day the changes are on gets History's heading before its first
  // row, as the answers of Answered earlier do (historyDay, an h3 under the
  // section's h2; §4.25 *Changes sit under their day*): the local day it
  // was made. The rows drawn are drawn together, so a Show more that
  // continues the last day adds no heading, and a search groups what it
  // finds. A change with no time starts no day. A heading has no data-id
  // nor data-proposal: drawnCards and markApprovalsAsk pass it by.
  let lastDay = null;
  for (const c of changes) {
    if (Number.isFinite(c.createdAt)) {
      const key = localDay(c.createdAt).key;
      if (key !== lastDay) host.append(historyDay(key, 1, 'h3').make());
      lastDay = key;
    }
    // Its state: whether Undo is on it, so the words of a refused Undo go
    // once it was undone.
    // `data-proposal`: the request it answered, which a link to that
    // request marks it by (markApprovalsAsk).
    const row = el('div', { class: 'row answered', 'data-id': c.id, 'data-proposal': typeof c.proposalId === 'string' ? c.proposalId : null, 'data-state': c.undoable ? 'undoable' : 'done' });
    // A change your agent made or asked for names that agent, and its
    // folder after the moment, when Home lists its session ("Claude Code
    // tightened your rules"; §4.25 *A rule change and the agent that asked*).
    const asker = changeAsker(c);
    const sentence = namedSentence(c, asker);
    const said = el('div', { text: sentence });
    nameBy(row, said);
    const list = rowList(c.rows, 'proposal-let');
    const words = el('div', { class: 'answered-sentence' }, said, list);
    // Two rows can share a sentence ("Your agent tightened your rules"):
    // their Undo and link are named by what each changed (*Details, Undo
    // and the agent link name their row*).
    const about = changeWords(sentence, list);
    // A change your agent made or asked for links its page at the top, as
    // the Rules origin line does (dashboard.md §4.25 *A rule change and the
    // agent that asked*).
    row.append(answeredWhat(words, c.createdAt, c.session ? { id: null, sessions: [c.session], about, from: changeFrom(asker) } : null));
    row.append(el('div', { class: 'dim', text: c.undone ? 'Undone' : '' }));
    if (c.undoable) {
      row.append(el('button', { type: 'button', class: 'btn small right', text: 'Undo', 'aria-label': rowControlName('Undo', about), onclick: () => undoChange(c, row) }));
    } else row.append(el('span'));
    host.append(row);
  }
  // Under a search or a day: the rows drawn of those found, and Show more
  // draws the next 20 from the read kept (moreChangesFound).
  if (finding && found.length > changes.length) {
    host.append(moreLine('changes-more', ['Showing ' + changes.length + ' of ' + n(found.length, 'change', 'changes') + (q ? ' that match' : '') + (day ? ' from ' + historyDayWords(day) + ' back' : '') + '.'], moreChangesFound));
  } else if (!finding && all.length > changes.length) {
    // No total to give: the newest shown, and Show more while one more came.
    host.append(moreLine('changes-more', st.failure
      ? cannotCheck('Could not read more of the rule changes.', st.failure, false)
      : ['Showing the newest ' + n(changes.length, 'change', 'changes') + '.'], () => loadRuleHistory(true)));
  }
  putBackAnswers('change', host);
  // Drawn again: a link to one of them marks it, whichever of this read and
  // Home's lands last.
  if (linksRuleChange()) markApprovalsAsk();
  if (!more) { pollRefocus(place); return; }
  const first = changes.find((x) => !had.includes(x.id));
  const row = r && first ? drawnCards(host).get(first.id) : null;
  if (row) landOn(row);
  else {
    const again = host.querySelector('.changes-more .show-rest');
    if (again && focusFell()) again.focus({ preventScroll: true });
  }
}

// ── Finding a rule change (dashboard.md §4.25 *Finding a rule change*) ─────
let changesSearchTimer = 0;
/** What Rule changes is drawn from (sameAsDrawn): the read, how many are
 *  drawn, each agent and folder Home names (changeAsker), every one under a
 *  search or a day, which matches them, the search and the day. */
function ruleHistoryKey() {
  const st = S.changes;
  const all = st.last && Array.isArray(st.last.changes) ? st.last.changes : [];
  return [st.last, st.want, st.failure, (changesFinding() ? all : all.slice(0, st.want)).map(changeAsker), S.changesQ, S.changesDay, st.failure ? offKey() : null];
}
/** Whether Rule changes is found by a search or a day (§4.25 *Finding a
 *  rule change*, *Go to a day on Rule changes*): it then reads the newest
 *  CHANGES_MAX and lists what it finds among them. */
function changesFinding() {
  return !!(S.changesQ || S.changesDay);
}
/** The changes of `all` made on the day `day` or before, newest first, as
 *  History cuts its sessions (historyDayEnd: before the next local day
 *  starts); a change with no time is kept, at the end, as History keeps a
 *  session with none. `all` itself when no day is set. */
function changesFromDay(all, day) {
  if (!day) return all;
  const end = historyDayEnd(day);
  return [...all.filter((c) => Number.isFinite(c.createdAt) && c.createdAt < end), ...all.filter((c) => !Number.isFinite(c.createdAt))];
}
/** The changes of `all` the search and the day of the page find. */
function changesFound(all) {
  const dated = changesFromDay(all, S.changesDay);
  return S.changesQ ? foundChanges(dated, S.changesQ) : dated;
}
/** Whether the read kept holds every change a search may find: the newest
 *  CHANGES_MAX, or fewer than the read asked for (every one there is). */
function changesComplete() {
  const st = S.changes;
  const all = st.last && Array.isArray(st.last.changes) ? st.last.changes : null;
  return !!all && (st.limit >= CHANGES_MAX || all.length < st.limit);
}
/** The words a search looks in for a change, in lower case: its sentence
 *  as drawn (with the agent Home names), that agent and its folder as
 *  `~/…`, each part of its rows (the file, the host, the program, the
 *  level) and "Undone" for an undone change. Never a moment. */
function changeSearchWords(c) {
  const asker = changeAsker(c);
  const words = [namedSentence(c, asker)];
  if (asker) words.push(asker.agent || '', asker.cwd ? shortPath(asker.cwd) : '');
  for (const row of Array.isArray(c.rows) ? c.rows : []) {
    for (const p of Array.isArray(row) ? row : []) if (p && p.kind !== 'time' && typeof p.text === 'string') words.push(p.text);
  }
  if (c.undone) words.push('Undone');
  return words.join(' ').toLowerCase();
}
/** The changes of `all` whose words hold every word of `q`, case aside,
 *  newest first. */
function foundChanges(all, q) {
  const want = q.toLowerCase().split(' ').filter(Boolean);
  return all.filter((c) => {
    const words = changeSearchWords(c);
    return want.every((w) => words.includes(w));
  });
}
/** The box and its count line, in `block`: hidden while there is no change
 *  and no search (the box keeps a focus it holds); "3 of 41 changes match",
 *  or "3 of the newest 500 changes match" when the read was cut there.
 *  Found from the block, as the rows are: a read can land after the page
 *  has gone. */
function drawChangesSearch(block, all, found) {
  const form = block.querySelector('#changes-search');
  const count = block.querySelector('#changes-count');
  if (!form || !count) return;
  const q = S.changesQ;
  const day = S.changesDay;
  form.hidden = !q && !day && all.length === 0 && !form.contains(form.ownerDocument.activeElement);
  const complete = changesComplete();
  const counted = (!!q || !!day) && complete && found.length > 0;
  const cut = all.length >= CHANGES_MAX;
  const of = cut ? 'the newest ' + CHANGES_MAX + ' changes' : n(all.length, 'change', 'changes');
  // A day (§4.25 *Go to a day on Rule changes*) says where the list starts,
  // "From Tuesday, Oct 20 back", after the count of a search; alone, and
  // over a read cut at CHANGES_MAX, that it is cut on those.
  const from = day ? 'from ' + historyDayWords(day) + ' back' : '';
  const said = !counted ? ''
    : q ? found.length + ' of ' + of + (found.length === 1 ? ' matches' : ' match') + (from ? ', ' + from : '')
      : from.charAt(0).toUpperCase() + from.slice(1) + (cut ? ', of ' + of : '');
  // None found: the sentence of the list, to a screen reader only (findCount).
  findCount(count, said, (q || day) && complete && !found.length ? changesNone(q, day, cut) : '');
}
/** What Rule changes says when a search or a day finds none; `cut`: the
 *  read held the newest CHANGES_MAX, so older changes may exist past them. */
function changesNone(q, day, cut) {
  const onDay = day ? ' on or before ' + historyDayWords(day) : '';
  if (q) return 'No change matches \u201c' + q + '\u201d' + onDay + (day && cut ? ', of the newest ' + CHANGES_MAX + ' changes' : '') + '.';
  return cut ? 'None of the newest ' + CHANGES_MAX + ' changes was made' + onDay + '.' : 'No rule changed' + onDay + '.';
}
/** Under a search, what the list says in place of rows: the read out, the
 *  read failed, or nothing found, each with Clear but the first. Whether
 *  rows are to be drawn. */
function drawChangesFound(host, changes) {
  if (changes.length && changesComplete()) return true;
  const st = S.changes;
  // A day has Show the newest in place of Clear, as Answered earlier has.
  const day = S.changesDay;
  const clearBtn = day
    ? el('button', { type: 'button', class: 'btn small history-clear history-newest', text: 'Show the newest' })
    : el('button', { type: 'button', class: 'btn small history-clear', text: 'Clear' });
  clearBtn.addEventListener('click', day ? showChangesNewest : clearChangesSearch);
  if (!changesComplete() && (st.last || !st.read)) host.append(el('div', { class: 'empty', text: 'Finding your changes\u2026' }));
  else if (!st.last) host.append(el('div', { class: 'empty' }, ...cannotCheck('Could not read your rule changes.', offCause(st.failure), false, CHANGES_OFF), ' ', clearBtn));
  else host.append(el('div', { class: 'empty' }, changesNone(S.changesQ, day, Array.isArray(st.last.changes) && st.last.changes.length >= CHANGES_MAX) + ' ', clearBtn));
  return false;
}
/** Rule changes drawn again from what it holds, when that changed. */
function renderRuleHistory() {
  if (sameAsDrawn('rule-history', ruleHistoryKey())) return;
  drawRuleHistory(false, null, [], document.getElementById('approvals-rule-history-block'), document.getElementById('approvals-rule-history'));
}
/** Show more under a search: the next CHANGES_PAGE of those found, from the
 *  read kept, whose first row takes the focus. */
function moreChangesFound() {
  const st = S.changes;
  const all = st.last && Array.isArray(st.last.changes) ? st.last.changes : [];
  const had = changesFound(all).slice(0, st.want).map((x) => x.id);
  st.want += CHANGES_PAGE;
  sameAsDrawn('rule-history', ruleHistoryKey());
  drawRuleHistory(true, st.last, had, document.getElementById('approvals-rule-history-block'), document.getElementById('approvals-rule-history'));
}
/** The words in the box, matched once the typing stops (HISTORY_SEARCH_MS),
 *  or at once (`now`: Enter, Escape or Clear). A search that changed lists
 *  the newest 20 of its matches, and writes itself into the address
 *  (replaced, not pushed); it drops a change the address opened with its
 *  mark, as Find an answer does. Only the first search of a visit reads
 *  (the newest CHANGES_MAX); the keys after it match that read. No search:
 *  the newest 20 again, with no read. */
function findChanges(text, now) {
  clearTimeout(changesSearchTimer);
  const run = () => {
    if (S.page !== 'approvals') return;
    const q = historyQuery(text);
    if (q === S.changesQ) return;
    const st = S.changes;
    S.changesQ = q;
    st.want = CHANGES_PAGE;
    if (S.approvalsAsk) {
      S.approvalsAsk = null;
      markApprovalsAsk();
    }
    const href = stateHref();
    if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
    changesFoundNow();
  };
  if (now) run();
  else changesSearchTimer = setTimeout(run, HISTORY_SEARCH_MS);
}
/** Rule changes drawn for the search and the day just set: with neither,
 *  its read cut as the poll reads without them, so its next read draws
 *  nothing again; with either, read when the read kept does not hold the
 *  newest CHANGES_MAX. */
function changesFoundNow() {
  const st = S.changes;
  if (!changesFinding() && st.last && Array.isArray(st.last.changes) && st.limit > CHANGES_PAGE + 1) {
    st.last = { ...st.last, changes: st.last.changes.slice(0, CHANGES_PAGE + 1) };
    st.limit = CHANGES_PAGE + 1;
  }
  renderRuleHistory();
  if (changesFinding() && !changesComplete()) loadRuleHistory();
}
/** Clear: the box empty, the newest changes listed again, the box focused. */
function clearChangesSearch() {
  const box = document.getElementById('changes-q');
  box.value = '';
  findChanges('', true);
  box.focus();
}
function wireChangesSearch() {
  const box = document.getElementById('changes-q');
  box.addEventListener('input', () => findChanges(box.value, false));
  document.getElementById('changes-search').addEventListener('submit', (e) => {
    e.preventDefault();
    findChanges(box.value, true);
  });
  // Escape empties the box (a plain one, and only with words in it), as in
  // Find an answer.
  box.addEventListener('keydown', (e) => {
    if (!plainEscape(e) || !box.value) return;
    e.preventDefault();
    clearChangesSearch();
  });
  // A date box fires `change` once a whole day is chosen or it is cleared.
  const day = document.getElementById('changes-day');
  day.addEventListener('change', () => setChangesDay(day.value));
  document.getElementById('changes-newest').addEventListener('click', showChangesNewest);
}

// ── Go to a day on Rule changes (dashboard.md §4.25) ────────────────────────
/** The box as the day of Rule changes says it: its value, today as its
 *  latest day, and Show the newest beside it while a day is set (as
 *  Answered earlier has, showAnsweredDay). */
function showChangesDay() {
  const box = document.getElementById('changes-day');
  if (box.value !== S.changesDay) box.value = S.changesDay;
  box.max = localDay(Date.now()).key;
  document.getElementById('changes-newest').hidden = !S.changesDay;
}
/** A day chosen in the box, or '' (cleared, or Show the newest): Rule
 *  changes lists the newest 20 from it back, with the search it has, and
 *  the address says so (replaced, not pushed); it drops a change the
 *  address opened with its mark, as a search does. No server read of its
 *  own: the newest CHANGES_MAX, cut on the page (changesFromDay). */
function setChangesDay(day) {
  if (S.page !== 'approvals') return;
  const next = historyDayParam(day);
  if (next === S.changesDay) return;
  S.changesDay = next;
  S.changes.want = CHANGES_PAGE;
  showChangesDay();
  if (S.approvalsAsk) {
    S.approvalsAsk = null;
    markApprovalsAsk();
  }
  const href = stateHref();
  if (location.pathname + location.search !== href) history.replaceState(history.state, '', href);
  changesFoundNow();
}
/** Show the newest: no day, the changes from the newest (with the search,
 *  if any), the box focused. */
function showChangesNewest() {
  setChangesDay('');
  document.getElementById('changes-day').focus();
}

/** Who made a rule change your agent made or asked for (`o.who`), as Home
 *  knows its session: the agent's name and folder, or null (§4.25 *A rule
 *  change and the agent that asked*). A Rule changes row and a rule's
 *  origin line, never anyone else's change. */
function changeAsker(o) {
  return o && (o.who === 'agent' || o.who === 'agent-approved') ? sessionAsker(o.session) : null;
}

/** The sentence of a Rule changes row or an origin line, naming the agent
 *  (`asker.agent`) between the words the server sent around it
 *  (`o.named`): "Claude Code tightened your rules". The server's sentence
 *  when the agent is not known. */
function namedSentence(o, asker) {
  const w = o.named;
  return asker && asker.agent && w && typeof w.before === 'string' && typeof w.after === 'string' ? w.before + asker.agent + w.after : o.sentence;
}

/** "· from Claude Code in ~/projects/shop" after the moment of a change the
 *  agent made, as the card of its request says it (askedFrom); null with no
 *  folder known. */
function changeFrom(asker) {
  return asker && asker.cwd ? askedFrom({ askerCwd: asker.cwd, askerAgent: asker.agent || 'your agent', askerSessions: 1 }) : null;
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
/** A read of Your rules has answered (or failed) on this page: until then
 *  Find a rule is left as drawn (rulesFindShown). */
let RULES_READ = false;
/** The version of your rules the drawn rules are at least as new as
 *  (`rulesVersion` of /api/home; dashboard.md §4.25 *Rules follows a change
 *  made elsewhere*). A read the page asks (Rules opened, a change made on
 *  it) forgets it: the first poll asked after that read (`after`, a count of
 *  S.homeAsked) gives it, without a read and without the line, so a change
 *  the page made itself never says it was made elsewhere. `readAt`: when
 *  the drawn read was asked, for the link of the line (rulesChangedLine).
 *  `out`: the number of the newest read while it is out (asked, not yet
 *  taken, dropped or failed), 0 when none is: a poll leaves the host ask
 *  to it only then (followHostWaiting). */
const RULES_SEEN = { version: null, after: 0, readAt: 0, out: 0 };

/** `opts.version`: a read of the follow (followRules), at the version it
 *  follows; the line under Your rules stays. Any other read is one the
 *  page asked itself, and takes the line away. */
async function loadRules(opts = {}) {
  const asked = RULES_READS.ask();
  RULES_SEEN.out = asked;
  try { await readRules(opts, asked); } finally {
    // However it ended (taken, dropped as older, failed): no longer out.
    if (RULES_SEEN.out === asked) RULES_SEEN.out = 0;
  }
}

async function readRules(opts, asked) {
  RULES_SEEN.version = typeof opts.version === 'string' ? opts.version : null;
  RULES_SEEN.after = S.homeAsked;
  RULES_SEEN.readAt = Date.now();
  // The file rows this read draws are at least as new as the questions the
  // last Home answer said wait (followFileWaiting): a send waiting since
  // then differs at the next poll, which reads again.
  const waitingAsked = waitingKey(S.home);
  if (waitingAsked !== null) F.waitingKey = waitingAsked;
  if (typeof opts.version !== 'string') rulesChangedLine(null);
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
  RULES_READ = true;
  if (AXES_READS.take(axesAsked)) { S.axes = axes; S.axesFollowed = null; }
  S.secrets = secrets; S.origins = origins && origins.origins ? origins : null;
  S.byWho = byWho;
  S.panel = panel && !panel.failed && panel.available !== false ? panel : null;
  S.panelFailure = (panel && panel.failed) || null;
  renderRulesOff();
  renderRulesPending();
  renderRulesFile();
  renderRules();
  renderByWho();
  // The answer asked again here has seen what waits now (followHostWaiting).
  recheckHost();
  renderMadeFromSecrets();
  // A file made from a secret, drawn before this read, says what wrote it now.
  const drawn = [F.data && F.data.self, F.typed && F.typed.label, ...F.entries.map((e) => e.label)];
  if ((F.data || F.typed) && drawn.some((l) => l && l.source === 'written')) renderFiles();
}

/** Rules follows a change made elsewhere (dashboard.md §4.25 *Rules follows
 *  a change made elsewhere*): the policy tools of your agent, an answer given
 *  in another tab or a notification, an edit to policy.yaml, Apply in Describe
 *  in a second tab. On each Home poll that answered (`asked`, its number)
 *  while Rules is shown: a `rulesVersion` that differs from the one drawn
 *  (RULES_SEEN) reads your rules again, and the open folder, keeping the
 *  place and the focus as the poll does, then says so (rulesChangedLine).
 *  The choices waiting in Changes to save keep the rule versions they were
 *  made against (no pendingVersionsNow, as syncFromOtherTab): a choice made
 *  before the change is still refused at Save, which then reads again.
 *  While the focus is in a text field on Rules nothing is read: the first
 *  poll after it leaves reads. A server with no `rulesVersion`: nothing. */
async function followRules(asked) {
  const v = S.home && S.home.rulesVersion;
  if (S.page !== 'rules' || tabHidden() || typeof v !== 'string' || asked <= RULES_SEEN.after) return;
  if (RULES_SEEN.version === null) { RULES_SEEN.version = v; return; }
  if (v === RULES_SEEN.version || rulesTyping()) return;
  const main = document.getElementById('main');
  const place = pollPlace(main);
  const readAt = RULES_SEEN.readAt;
  const [, , changes] = await Promise.all([
    loadRules({ version: v }),
    F.path ? openFolder(F.path, { again: true }) : null,
    // The newest rule change, for the link of the line: only on a follow.
    apiGetControl('policy/changes?limit=1').then((r) => (r && r.ok && r.data ? r.data.changes : null), () => null),
  ]);
  // A read the page asked meanwhile (a save) is newer: it draws, not this.
  if (RULES_SEEN.version !== v || S.page !== 'rules') return;
  const newest = Array.isArray(changes) ? changes[0] : null;
  rulesChangedLine(newest && Number.isFinite(newest.createdAt) && newest.createdAt >= readAt ? newest.id : null, true);
  if (place) pollRefocus(place);
}

/** The focus is in a text field on Rules (Find a rule, a host box, the
 *  reason box, Describe): a read now could redraw under the keys of the person. */
function rulesTyping() {
  const x = document.activeElement;
  const page = document.getElementById('page-rules');
  if (!x || !page || !page.contains(x)) return false;
  if (x.isContentEditable || x.tagName === 'TEXTAREA') return true;
  return x.tagName === 'INPUT' && !/^(checkbox|radio|button|submit|reset|range|color|file|image)$/.test(x.type);
}

/** The line under the heading of Your rules after a follow (followRules): "Your
 *  rules changed since this page was read. It shows them now.", with "See
 *  the change in Approvals" when the newest rule change has an id and was
 *  made since the drawn read (changesLink). `show` false: hidden. */
function rulesChangedLine(changeId, show) {
  const line = document.getElementById('rules-changed');
  if (!line) return;
  clear(line);
  line.hidden = !show;
  if (!show) return;
  line.append('Your rules changed since this page was read. It shows them now.');
  const link = changesLink(changeId, 'See the change in Approvals');
  if (link) line.append(' ', link);
}

/** Where your rules are kept, and an edit to that file Mandu refused
 *  (dashboard.md §4.25 *Rules says where your rules file is*; the banner of
 *  policy-surface.md §2.1). The panel reports the file as `policyFile`. A
 *  hand edit the protection service finds not valid is refused, and the last
 *  version that worked stays in force: the line above Your rules says so,
 *  with the problems, each as text (they can echo the file). Otherwise a dim
 *  note under the intro of Your rules names the file. No file named (an
 *  older service, rules kept in memory): nothing. */
const REFUSED_SHOWN = 5;
function renderRulesFile() {
  const refused = document.getElementById('rules-refused');
  const note = document.getElementById('rules-file');
  if (!refused || !note) return;
  const f = S.panel && S.panel.policyFile;
  const path = f && typeof f.path === 'string' && f.path ? f.path : null;
  const problems = path && Array.isArray(f.problems) ? f.problems.filter((p) => typeof p === 'string' && p !== '') : [];
  const at = path && Number.isFinite(f.refusedAt) ? f.refusedAt : null;
  if (sameAsDrawn('rules-file', path ? [path, !!f.found, f.valid !== false, problems, at] : null)) return;
  clear(refused);
  clear(note);
  if (path && f.valid === false) {
    refused.append('Your last edit to ', nameCode(shortPath(path)), ' has a mistake, so Mandu is still using the last version that worked',
      ...(at === null ? [] : [' (since ', momentNode(new Date(at).toISOString()), ')']),
      '. Your rules below are the ones in force. Fix the file and save it; Mandu reads it again within seconds.');
    if (problems.length) {
      const list = el('ul', { class: 'rules-refused-problems' });
      const shown = problems.slice(0, REFUSED_SHOWN);
      shown.forEach((p, i) => {
        const more = i === shown.length - 1 && problems.length > shown.length ? ', and ' + (problems.length - shown.length) + ' more' : '';
        list.append(el('li', { text: problemWords(p) + more }));
      });
      refused.append(list);
    }
  } else if (path && f.found) {
    note.append('Saved in ', nameCode(shortPath(path)), '. Mandu also reads your hand edits to it.');
  } else if (path) {
    note.append('Your rules will be saved in ', nameCode(shortPath(path)), ' when you add one.');
  }
  refused.hidden = !refused.firstChild;
  note.hidden = !note.firstChild;
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
  if (sameAsDrawn('rules-pending', [k, onDisk, oneProposal(S.proposals)])) return;
  clear(box);
  if (k) {
    box.append(
      onDisk
        ? 'policy.yaml has a change that waits for your OK, so it is not in force yet. '
        : n(k, 'rule change waits', 'rule changes wait') + ' for your OK. ',
      'Until you answer, the rules below are the ones Mandu enforces. ',
      proposalsLink(S.proposals, { text: 'Review ' + (k === 1 ? 'it' : 'them') + ' in Approvals' }),
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
  // Not running, the sentence names the commands that start your agent
  // (`start`): a scan run meanwhile can change them.
  return p ? (p.connected ? 'connected' : p.notRunning ? 'not running:' + startList(home).join(',') : 'not connected') + ':' + p.level : 'no home';
}
/** The Home poll: Settings › Protection and the Rules line follow what runs
 *  (the first paint of a direct visit may come before Home answers, and a
 *  restart changes what runs while the page is open). */
function followRunning() {
  followServiceQuiet();
  if (!S.axes) return;
  const key = runningKey(S.home);
  if (S.runningShown.settings !== key) renderProtection();
  if (S.runningShown.rules !== key) renderRulesOff();
}

/** The Home poll: the other lines that say whether protection runs follow
 *  a restart on or off too, read from the protection service's own state
 *  (dashboard.md §4.25 *The on/off says what runs*): on Settings, the
 *  Prompt filters card is read again (its "Protection is off" note, and a
 *  drawn Try a message answer with it, promptTryAgain); on Rules, each
 *  "What the rules say" and a Find a rule answer is asked again
 *  (readWhyRunning). Keyed on the on/off alone, once per change and per
 *  page (`S.runningFollowed`), so a poll that leaves it reads nothing, and
 *  a restart made from Settings is still followed on returning to Rules;
 *  an unknown on/off (a restart under way says "not connected") is no
 *  change. Never under the person's hands: the first poll after reads. */
function followRunningAnswers() {
  const now = secretsRunning(S.home);
  const page = S.page === 'settings' || S.page === 'rules' ? S.page : null;
  if (now === null || !page || tabHidden()) return;
  const was = S.runningFollowed[page];
  if (was === now) return;
  if (page === 'settings' ? promptUnderHands() : whyUnderHands()) return;
  S.runningFollowed[page] = now;
  // First seen on this page: its own reads are as new as this poll.
  if (was === null) return;
  if (page === 'settings') loadPromptSettings();
  else readWhyRunning();
}
/** Settings › Prompt filters is in use: the focus in the card, an exception
 *  being written, a menu choice waiting for Enter or a question of the card
 *  open. Its read would draw the card anew under them. */
function promptUnderHands() {
  const block = document.getElementById('settings-prompt-block');
  if (block && block.contains(document.activeElement)) return true;
  const match = document.getElementById('prompt-exception-match');
  if (match && match.value.trim()) return true;
  if (ASKING && String(ASKING.key).startsWith('prompt')) return true;
  return [...MENU_WAITS.keys()].some((k) => k.startsWith('prompt:'));
}
/** Find a rule's answer holds the focus (its Clear, Show that rule, add a
 *  rule): drawing it again would take the focus away. */
function whyUnderHands() {
  const box = document.getElementById('rules-find-none');
  return !!(box && box.contains(document.activeElement));
}

/** On/off on the secrets axis of a saved mode, as the switch shows it:
 *  null when it names none. */
function savedSecrets(mode) {
  return mode === 'secrets' || mode === 'full' ? 'on' : mode === 'off' || mode === 'injection' ? 'off' : null;
}
/** The Home poll: Settings › Protection and the Rules line follow the
 *  setting SAVED elsewhere (another tab, `mandu mode`, an edit of
 *  config.toml), as the top bar does (dashboard.md §4.25 *The protection
 *  switch keeps what you saved*). Home's `protection.configured` is the
 *  saved setting; one that differs from the one drawn reads config/axes
 *  again, once per value (`S.axesFollowed`), never while a flip is out or
 *  the focus is in the OFF box (the first poll after reads). */
function followSaved() {
  if ((S.page !== 'settings' && S.page !== 'rules') || tabHidden()) return;
  const drawn = S.axes && S.axes.effective ? (S.axes.effective.confidentiality ? 'on' : 'off') : null;
  const polled = savedSecrets(S.home && S.home.protection && S.home.protection.configured);
  if (!drawn || !polled || polled === drawn || polled === S.axesFollowed || S.protectOut) return;
  const box = document.getElementById('settings-protect-confirm');
  if (box && !box.hidden && box.contains(document.activeElement)) return;
  S.axesFollowed = polled;
  readSavedAgain(drawn);
}
/** The follow's read (followSaved). A failure keeps what was drawn, and is
 *  not taken, so an older read still draws; the same on/off draws nothing
 *  (a refusal in the note stays); another is drawn, and a status line says
 *  the switch moved. */
async function readSavedAgain(drawn) {
  const asked = AXES_READS.ask();
  const axes = await apiGet('config/axes').catch(() => null);
  if (!axes || !axes.effective || !AXES_READS.take(asked)) return;
  S.axes = axes;
  S.axesFailure = null;
  const now = axes.effective.confidentiality ? 'on' : 'off';
  if (now === drawn) return;
  renderProtection();
  renderRulesOff();
  // It cannot know who changed it: never "your agent".
  protectChanged('Changed outside this page: saved as ' + now + '.');
}
/** The status line of Settings › Protection that says the switch moved by
 *  itself (followSaved); empty and hidden at the page's own read or flip. */
function protectChanged(words) {
  const line = document.getElementById('settings-protect-changed');
  if (!line) return;
  line.textContent = words || '';
  line.hidden = !words;
}

/** Under a "your own model only" rule while no model of your own is listed
 *  (the same words as model-endpoints.ts NO_OWN_MODEL_WARNING), the place a
 *  link to Settings at its Models card. */
const NO_OWN_MODEL_WARNING = ownWords('No AI of your own is listed, so no AI reads this file. Add one in ', { to: 'models', text: 'Settings › Models' }, '.');
/** A rule row warning: the server parts (its place a link), else the words
 *  as words() draws them, a sentence of this page with its link. */
function warningWords(r) {
  return r.warningParts ? textParts(r.warningParts, r.warning) : words(r.warning);
}

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
  S.axesFollowed = null;
  protectChanged(null);
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
    closeOffBox(false);
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
  // The OFF box asks only while on is saved: saved off elsewhere, it goes.
  // Else a redraw leaves it, and what was typed in it, as it is.
  if (!on) closeOffBox(false);
  name.append(el('span', { class: 'dot ' + protectDot() }), on ? 'On' : 'Off');
  // The words Home uses: a rule sends a secret with no question asked, so
  // the row never promises an OK for every send (dashboard.md §4.25d).
  const ON_WORDS = 'Keys and secret files leave this computer only where a rule or your OK allows.';
  const OFF_WORDS = 'Mandu only watches. Your secrets are not masked, and nothing is stopped.';
  if (now === null) {
    const connected = !!(S.home && S.home.protection && S.home.protection.connected);
    const notRunning = !!(S.home && S.home.protection && S.home.protection.notRunning);
    const saved = 'Saved as ' + (on ? 'on' : 'off') + '. ';
    clear(text);
    // Mandu is not running at all (§4.25, *Protection is off when nothing
    // runs*): the commands as code with Copy, as Home draws them; the
    // service line under it then says only Stopped (drawServices).
    if (!connected && notRunning) text.append(saved + 'Mandu is not running now, so no agent is protected. It starts with your first agent: ', ...startRunCodes(S.home), '.');
    else text.textContent = saved + (connected
      ? 'Mandu cannot say what the protection service runs now.'
      : 'The protection service is not reachable, so Mandu cannot say what is on now.');
  } else if ((now === 'on') === on) text.textContent = on ? ON_WORDS : OFF_WORDS;
  else text.textContent = now === 'on'
    ? 'Still on until the protection service restarts: keys and secret files leave this computer only where a rule or your OK allows.'
    : 'Still off until the protection service restarts: Mandu only watches, and your secrets are not masked.';
  const running = S.home && S.home.protection.level;
  const waits = running && running !== 'unknown' && running !== a.effectiveMode;
  // When it was last turned off or on here, if the record says so
  // (protectionChangedLead); then "It applies …", the lead saying it was
  // saved already, else today's sentence alone.
  const lead = protectionChangedLead(a, on);
  clear(note);
  note.append(...(lead || []), lead && waits ? 'It applies when the protection service next starts.'
    : waits ? 'Saved. It applies when the protection service next starts.'
    : 'A change applies when the protection service next starts.');
}

/** The lead of the Protection row's note: when it was last turned off or on
 *  in the dashboard (dashboard.md §4.25 *The Protection row says when it was
 *  last turned off or on in the dashboard*): "Turned off in the dashboard
 *  Oct 30, 14:05 · 3 days ago. ", from the latest confidentiality
 *  `config_change` record config/axes answers as `audit`. Only a record
 *  whose `to` is the saved on/off counts: else `mandu mode` or an edit of
 *  config.toml changed it since and left no record, and the page never
 *  guesses a time (null, as with no record or a `ts` that does not parse).
 *  `requestedBy` is never drawn, and the frozen integrity axis is not read. */
function protectionChangedLead(a, on) {
  const rec = a && a.audit && a.audit.confidentiality;
  if (!rec || rec.to !== on || typeof rec.ts !== 'string') return null;
  const at = whenNode(Date.parse(rec.ts));
  return at ? [(on ? 'Turned on' : 'Turned off') + ' in the dashboard ', at, '. '] : null;
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
  // again, or open the OFF box again. A press to turn it off opens the box
  // (askOff), whose Turn off posts; a press to turn it on posts at once.
  if (S.protectOut) return;
  if (!on) {
    askOff();
    return;
  }
  return sendProtection(true);
}

/** Turning protection off asks on the page, in a box in the Protection row
 *  (dashboard.md §4.25 *Turning protection off asks on the page*): one
 *  sentence, a box for the word OFF in any case (confirmBox), Turn off and
 *  Cancel. Escape or Cancel close it and give the switch the focus back. A
 *  second press while it is open puts the focus in the box. */
function askOff() {
  const host = document.getElementById('settings-protect-confirm');
  if (!host.hidden) {
    const typed = host.querySelector('input');
    if (typed) typed.focus();
    return;
  }
  clear(host);
  const turnOff = el('button', { type: 'button', class: 'btn small primary', text: 'Turn off', onclick: () => sendProtection(false) });
  const cancel = el('button', { type: 'button', class: 'btn small', text: 'Cancel', onclick: () => closeOffBox(true) });
  const box = confirmBox(turnOff, 'Type OFF to turn protection off', '', null, () => S.protectOut,
    { word: 'OFF', hint: 'Type the word OFF to turn protection off.' });
  host.append(
    el('p', { id: 'settings-protect-ask', text: 'Turning this off lets your secrets leave this computer. Type OFF to turn it off.' }),
    el('div', { class: 'protect-confirm-foot' }, box.input, el('div', { class: 'protect-confirm-actions' }, turnOff, cancel)),
    box.hint);
  // Not once Turn off is on its way: it cannot be called back.
  host.onkeydown = (e) => {
    if (!plainEscape(e) || S.protectOut) return;
    e.preventDefault();
    closeOffBox(true);
  };
  host.hidden = false;
  box.input.focus();
}

/** Close the OFF box. The focus goes to the switch when asked (`back`), or
 *  when it was in the box, so it never falls to the page. */
function closeOffBox(back) {
  const host = document.getElementById('settings-protect-confirm');
  if (!host || host.hidden) return;
  const had = host.contains(document.activeElement);
  host.hidden = true;
  clear(host);
  const sw = document.getElementById('switch-protection');
  if ((back || had) && sw && !sw.disabled) sw.focus();
}

async function sendProtection(on) {
  // Not `disabled`, which drops the focus to the page: `aria-disabled` keeps
  // the focus on the switch and says it is off-limits, and a press is
  // ignored (flipProtection). A redraw meanwhile (the Home poll, a read of
  // the setting) leaves it as it is.
  if (S.protectOut) return;
  const keepIntegrity = !!(S.axes.integrityAllowed && S.axes.effective.integrity);
  const mode = on ? (keepIntegrity ? 'full' : 'secrets') : (keepIntegrity ? 'injection' : 'off');
  const sw = document.getElementById('switch-protection');
  // Held until the answer, whatever it is: every request answers (answerOf).
  S.protectOut = true;
  sw.setAttribute('aria-disabled', 'true');
  // The OFF box holds with the switch: Turn off and Cancel go off, and the
  // focus, from the box, goes to the held switch, where it stays through the
  // answer. The answer closes the box, so the next press asks again.
  const host = document.getElementById('settings-protect-confirm');
  if (host && !host.hidden) {
    const inBox = host.contains(document.activeElement);
    for (const b of host.querySelectorAll('button')) b.disabled = true;
    if (inBox) sw.focus();
  }
  let r;
  try { r = await apiPost('config/axes', { mode }); } finally {
    S.protectOut = false;
    sw.removeAttribute('aria-disabled');
    closeOffBox(false);
    protectChanged(null);
  }
  if (!r.ok) {
    setWords(document.getElementById('settings-protect-note'), refusalText(r, 'could not save the change (' + r.status + ')'));
    return;
  }
  AXES_READS.wrote();
  S.axes = r.data;
  S.axesFollowed = null;
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
// The line of each group is true of every row it holds, the blocking ones
// too (§4.25e): Sending data holds Always blocked sends, Programs and
// connections blocked commands and built-in checks set to Block.
const RULE_GROUPS = [
  // Your file rules are the Files and folders list above (§4.25n); what is
  // left of this group is your answers about single files.
  { key: 'files', title: 'Your answers about files',
    about: 'what you answered when Mandu asked about one file' },
  { key: 'send', title: 'Sending data',
    about: 'where masked data and secrets may go, or are blocked from going, without asking you' },
  { key: 'sources', title: 'Trusted sources',
    about: 'places whose content reaches the AI unmasked' },
  { key: 'run', title: 'Programs and connections',
    about: 'programs whose output the AI may read, connections the agent may open, and commands and checks you allow or block' },
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
/** A host's send rule in the Secrets mode (dashboard.md §4.25e *A send rule
 *  says when the mode leaves it nothing to decide*): the gate asks a rule for
 *  a host only about data that is not a secret, and with confidentiality on
 *  and integrity off only secrets are masked (a prompt filter masks at a
 *  secret level, never public), so the rule decides nothing. It is kept, and
 *  decides again in a mode with the integrity axis on. Axes unread: false;
 *  an expired rule already says it is no longer used. */
const SEND_RULE_KINDS = ['release-allow', 'release-block', 'release-audit'];
const SEND_RULE_IDLE_WORDS = 'Decides nothing in the Secrets mode: a rule for a host never covers your secrets, and this mode masks only secrets.';
/** The Secrets mode in force (confidentiality on, integrity off), as the
 *  Rules load read it; false while the axes are unread. */
function secretsModeOnly() {
  const a = S.axes && S.axes.effective;
  return !!(a && a.confidentiality && !a.integrity);
}
function sendRuleIdle(r) {
  return secretsModeOnly() && SEND_RULE_KINDS.includes(r.kind) && !r.expired;
}
/** A suggested edit that is a host's send rule (`op: "release"`: allow,
 *  block or audit) in the Secrets mode: Describe's card says so before
 *  Apply, in the same words (dashboard.md *A suggested send rule says when
 *  the mode leaves it nothing to decide*). */
function editIdle(edit) {
  return secretsModeOnly() && !!edit && typeof edit === 'object' && edit.op === 'release';
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
// whose words hold its text, case-insensitive. Presentation only: no write,
// and one read only for a full path no row holds (findWhyFor). Never in the
// address, and emptied by a page change (setPage), so a
// filter you forgot never makes a rule look missing on your next visit. Changes
// to save is never narrowed: it lists F.pending, not the rows drawn.

/** The text the rows are narrowed to: '' when the box is empty. */
function findText() {
  return String(S.ruleFind || '').replace(/\s+/g, ' ').trim().toLowerCase();
}
/** The words a row of Your rules draws, and only those (never the raw
 *  subject a row keeps for its tooltip, nor anything a read held back),
 *  and a row's one search-only word (`find`: the category id of a held
 *  message's answer that names its kind in words):
 *  - a file or folder of the tree: its path as drawn (`~/…`, and in full,
 *    its tooltip), its reach, its label, the Opens it line where the row
 *    draws one (opensShown), the hosts it may be sent to (per value, with
 *    the value's name);
 *  - any other row: what it covers (a host, a program, an address and
 *    port, a source), its second line (the file it sends, from where), and
 *    what it does. */
function ruleWords(r) {
  if (F.rules.includes(r)) {
    return [shortPath(r.path), r.path, r.reach, r.effect,
      opensShown(r) ? r.opens : null,
      ...(r.bindings || []), ...(r.values || []).flatMap((v) => [v.key, ...(v.bindings || [])])];
  }
  return [r.subject, r.reach, r.effect, r.until ? untilWords(r.until) : null, r.find];
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
  forgetFindWhy();
  if (!S.ruleFind) return;
  S.ruleFind = '';
  if (redraw) renderRules();
}
/** Under the heading while nothing drawn holds the text: says so, with
 *  Clear, and Add a rule when the text looks like a path. A full path says
 *  what covers it (findCovers). */
function renderFindNone(q, none) {
  const box = document.getElementById('rules-find-none');
  if (!box) return;
  clear(box);
  const typed = document.getElementById('rules-find').value.trim();
  const asking = !!(q && none && isFullPath(typed));
  if (!asking) forgetFindWhy();
  if (q && none) {
    box.append(el('p', null, 'No rule mentions \u201c' + typed + '\u201d. ',
      el('button', { type: 'button', class: 'link-btn', text: 'Clear', onclick: () => {
        // Focused first: a box emptied with no rule left stays (rulesFindShown).
        document.getElementById('rules-find').focus();
        clearRuleFind(true);
      } })));
    const st = asking ? findWhyFor(typed) : null;
    if (st && st.loading) box.append(el('p', { class: 'dim', text: 'Checking what covers it\u2026' }));
    else if (st && st.why) box.append(...findCovers(st.why, typed));
    else if (looksLikePath(q)) box.append(el('p', { class: 'dim' }, 'To make one, ', findAddRule(typed), '.'));
  }
  box.hidden = !box.firstChild;
}
/** Add a rule, for the text typed: a full path or a pattern goes in the
 *  path box and is opened, as Go opens it; any other text opens the
 *  browser where it starts. */
function findAddRule(typed) {
  return el('button', { type: 'button', class: 'link-btn', text: 'add a rule', onclick: () => {
    const full = /^(?:\/|~|\*\*\/)/.test(typed);
    setFilesView('all', null, full);
    const path = document.getElementById('lock-path');
    if (full) {
      path.value = typed;
      document.getElementById('files-go').requestSubmit();
    }
    path.focus();
  } });
}

// ── What covers a path no rule names (dashboard.md §4.25f *A path no rule
// names says what covers it*). A full path typed in Find that no row holds
// is asked of GET files/why (the read an opened row of the browser makes), once,
// FIND_WHY_DELAY ms after typing stops; an answer for text no longer in the
// box is dropped, and a read that fails leaves the plain lines.
const FIND_WHY_DELAY = 400;
const FIND_WHY = { text: null, state: null, timer: 0, seq: 0 };
/** A path written in full: from / or ~, not a pattern. */
function isFullPath(t) {
  return /^(?:\/|~(?:\/|$))/.test(t) && !/[*?[]/.test(t);
}
/** What is known of `typed`: { loading } while the read waits or is out,
 *  { why } once answered, null when the read failed. Asks when new. */
function findWhyFor(typed) {
  if (FIND_WHY.text === typed) return FIND_WHY.state;
  forgetFindWhy();
  FIND_WHY.text = typed;
  FIND_WHY.state = { loading: true };
  FIND_WHY.timer = setTimeout(() => readFindWhy(typed), FIND_WHY_DELAY);
  return FIND_WHY.state;
}
function forgetFindWhy() {
  if (FIND_WHY.timer) clearTimeout(FIND_WHY.timer);
  FIND_WHY.text = null;
  FIND_WHY.state = null;
  FIND_WHY.timer = 0;
}
async function readFindWhy(typed) {
  FIND_WHY.timer = 0;
  if (FIND_WHY.text !== typed) return;
  const mine = ++FIND_WHY.seq;
  const r = await apiGetControl('files/why?path=' + encodeURIComponent(typed)).catch(() => null);
  // Typed on meanwhile (or emptied, or a row now holds it), or asked again
  // since (readWhyRunning): not this answer.
  if (FIND_WHY.text !== typed || FIND_WHY.seq !== mine) return;
  const why = r && r.ok && r.data && r.data.why;
  FIND_WHY.state = why && why.label && typeof why.label.source === 'string' ? { why } : null;
  renderFindNone(findText(), true);
}
/** The lines that say what covers a path, in the words of fileLabel: the
 *  covering line with its link, then (when something covers it) the offer
 *  of a rule of its own. Says only what the label decided: "covers it",
 *  never "safe". */
function findCovers(why, typed) {
  const l = why.label;
  const level = () => el('em', { text: l.words });
  const via = l.via ? shortPath(String(l.via)).replace(/(.)\/+$/, '$1') : '';
  const line = el('p', { class: 'dim' });
  const own = el('p', { class: 'dim' }, 'To give it a rule of its own, ', findAddRule(typed), '.');
  let offer = true;
  if (l.source === 'inherited' || l.source === 'yours' || l.source === 'pattern') {
    // A long path breaks at its slashes (longName).
    const at = longName(el('code', { text: via }));
    if (l.source === 'pattern') line.append('It matches your rule ', at, ': ', level(), '.');
    else line.append('Your rule on ', at, ' covers it: ', level(), '.');
    const r = F.rules.find((x) => shortPath(x.path).replace(/(.)\/+$/, '$1') === via);
    if (r) line.append(' ', el('button', { type: 'button', class: 'link-btn', text: 'Show that rule', onclick: () => showFindRule(r, via) }));
    // Its own rule already: nothing to offer.
    if (l.source === 'yours') offer = false;
  } else if (l.source === 'builtin') {
    line.append('Mandu keeps it secret without a rule (' + l.from + '): ', level(), '. ', findSection('See Built-in protections', 'rules', 'built-in', 'builtin-block'));
  } else if (l.source === 'written') {
    line.append('Mandu keeps it secret because something holding a secret wrote it. ', findSection('See Files made from your secrets', 'rules', 'made-from', 'made-from-block'));
  } else if (l.source === 'model-key') {
    line.append('It is the key of a model in Settings \u203a Models. ', findSection('Open Settings \u203a Models', 'settings', 'models', 'settings-models-block'));
  } else {
    line.append('No rule and no built-in protection covers it. To protect it, ', findAddRule(typed), '.');
    offer = false;
  }
  if (why.off) line.append(' Protection is off, so none of this is enforced now.');
  return offer ? [line, own] : [line];
}
/** A link to a card, opened as the section links of the page open it. */
function findSection(text, page, key, id) {
  return el('a', { href: routeHref(page) + '#' + key, text, onclick: (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button > 0) return;
    e.preventDefault();
    goToSection(page, key, id);
  } });
}
/** Show that rule: its path in the box, Find run again, and its row opened
 *  with the folders above it unfolded (openRuleRow). */
function showFindRule(r, via) {
  const box = document.getElementById('rules-find');
  box.value = via;
  S.ruleFind = via;
  renderRules();
  openRuleRow(r.path);
}
/** An empty Your rules has nothing to find (§4.25f): the box is hidden
 *  while the rules were read and there is none, or could not be read
 *  (`any` false), and shown with the first rule. Never hidden while it
 *  holds text or has the focus, and left as drawn before the first read. */
function rulesFindShown(any) {
  const box = document.getElementById('rules-find');
  if (!box) return;
  if (box.value || document.activeElement === box) box.hidden = false;
  else if (RULES_READ) box.hidden = !any;
}
function wireRuleFind() {
  const box = document.getElementById('rules-find');
  box.addEventListener('input', () => {
    S.ruleFind = box.value;
    renderRules();
    // A list narrowed without a scroll: its place is the top (savePlace).
    savePlace();
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
  // A question asked in the list (askBox) is drawn again: a focus in it
  // that fell with the old box goes to the same part of the new one.
  const held = askHeld();
  drawRules();
  askRefocus(held);
}
function drawRules() {
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
        // Nothing at its path on this computer (§4.25f *A rule on nothing
        // says so*): a line under its name, the file icon; the rule as is.
        missing: isFile && r.missing === true,
        // For the side panel of the explorer (§4.25n): the label buttons press the
        // level in force and fill in its hosts; Remove there needs an edit op.
        level: isFile ? r.level : null,
        bindings: isFile ? (r.bindings || []) : null,
        // The rule's version as read: a label chosen on it sends it back
        // (dashboard.md §4.25m *A save names the rules as they were read*).
        version: isFile ? (r.version || null) : null,
        opens: isFile ? (words.opens || null) : null,
        // No `readers:` on the rule: its Opens it words are the default,
        // said once under the caption (renderFilesOpensNote), not on the row.
        opensDefault: isFile && words.opensDefault === true,
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
        // A send rule with an end still to come: that moment (ISO), drawn
        // after its effect (§4.25u, *A rule with an end date says when*).
        until: typeof words.until === 'string' && words.until ? words.until : null,
        // The menu of a send rule has the dot an answer with the same words
        // has (§4.25u, the dot of a send rule): red for Always blocked,
        // green for Always allowed; expired, audit or off, grey. A connection
        // or a built-in protection set to Block has no menu: its words take
        // the ✓ or ✗ of an answer without one (§4.25u, a connection rule is
        // coloured as its answer).
        // In the Secrets mode a host's send rule decides nothing
        // (sendRuleIdle): a line says so, and its dot is grey.
        modeNote: sendRuleIdle(r) ? SEND_RULE_IDLE_WORDS : null,
        effectClass: sendRuleIdle(r) ? null : ruleTone(r),
        used: r.hits === null || r.hits === undefined ? '' : r.hits === 0 ? 'Never used' : n(r.hits, 'use', 'uses'),
        // When it last decided something (useLine): an arbiter that counts
        // without a moment, or a rule never used, has none.
        hits: r.hits,
        lastHit: r.hits > 0 && Number.isFinite(r.lastHit) ? r.lastHit : null,
        flip: acts.flip ? { text: acts.flip === 'allow' ? 'Always allowed' : 'Always blocked', run: (row) => changeRule(r, acts.flip, row) } : null,
        remove: acts.remove ? (row) => changeRule(r, 'remove', row) : null,
        note: acts.flip || acts.remove ? null : 'Set in policy.yaml',
        sourceId: r.id,
        // What its *Find its changes* searches (changeFindTerm).
        ruleKind: r.kind,
        origin: ruleOrigin(r.id),
        warning: r.warning || null,
        warningParts: r.warning ? partsOf(r.warningParts) : null,
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
      // A rule made here says so too when nothing is at its path (§4.25f
      // *A rule on nothing says so*); ruleMissing leaves patterns out.
      missing: l.missing === true,
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
  // A file row names the answers about that file (fileAnswersLine) and the
  // sends of it that wait for one (fileWaitingLine): drawn from the same
  // answers as the rows below, so read again with them.
  F.answers = new Map();
  F.waiting = new Map();
  if (panel && panel.verdictsKnown) {
    for (const v of panel.queue) {
      keepFileWaiting(v);
      if (v.status === 'pending' || v.scope === 'once') continue;
      keepFileAnswer(v);
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
        // A known kind in words ("A card number …"), an organization's own
        // category as code; an older server sends none.
        subjectParts: partsOf(words.subjectParts),
        // A kind named in words keeps its id in the tooltip and in what Find
        // a rule matches (§4.25u *Rules names a held message's answer*), so a
        // rule written by id is still found.
        title: prompt ? (words.category ? words.subject + ' (' + words.category + ')' : words.subject) : v.target || v.subject,
        find: prompt && words.category ? words.category : null,
        reach: words.reach,
        // The file, address or command the answer covers, as code (§4.25u,
        // *Rules names what a send covers*); an older server sends none.
        reachParts: partsOf(words.reachParts),
        // A message's answer says what went to the AI, as Approvals does
        // (§4.25u *A held message's answer says what was sent*): masked is
        // not "Always blocked", since the message was not stopped.
        // A send of a program keyed to a session is kept on the row of that
        // session, so its effect says so, as Approvals does (§4.25 *Kept for one
        // session or one use*); a row listed here is a standing one, so a
        // once kind reads as it is kept, Always.
        effect: prompt ? messageEffect(v.status === 'approved') : answerEffectWords(v.status === 'approved', v.allowKeptAs === 'session' ? 'session' : null),
        effectClass: v.status === 'approved' ? 'ok' : 'bad',
        used: 'Your answer' + (v.count > 1 ? ', asked ' + v.count + ' times' : ''),
        sourceNote: 'Saved when you answered, not in policy.yaml',
        // Where it was asked (dashboard.md §4.25h): the session the ask was
        // raised in (the latest, as Approvals links it) and when you answered.
        asked: { id: v.id, session: v.sessions && v.sessions.length ? v.sessions[v.sessions.length - 1] : null, sessions: (v.sessions || []).length, answeredAt: v.resolvedAt },
        // The flip names what the arbiter keeps the new answer as.
        flip: flip ? { text: prompt ? messageEffect(flip.approve) : answerEffectWords(flip.approve, v.allowKeptAs), run: (row) => answerAgain(v.id, flip.approve, row, prompt, v.allowKeptAs) } : null,
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
  rulesFindShown(!!panel && rows.length > 0);
  // Find a rule (§4.25f): the count says how many of them the box keeps.
  const q = panel ? findText() : '';
  const found = rows.filter((r) => ruleMatches(r, q)).length;
  document.getElementById('rules-count').textContent = !rows.length ? '' : q ? found + ' of ' + rows.length : String(rows.length);
  renderFindNone(q, found === 0);
  renderExplorer();
  const rest = rows.filter((r) => !F.rules.includes(r) && ruleMatches(r, q));
  // A row the box hides is closed: its ⋯ is gone with it.
  if (q && S.openRule && !rest.some((r) => ruleRowKey(r) === S.openRule)) S.openRule = null;
  // A question about a row not drawn (the box hides it, the rule is gone)
  // ends: nothing was changed.
  if (ASKING && ASKING.key.startsWith('rule:') && !rest.some((r) => 'rule:' + ruleRowKey(r) === ASKING.key)) ASKING = null;
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
      const ask = ruleAsk(r);
      if (ask) list.append(ask);
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
 * { kind: 'folder', label, full, pattern, count, missing, children }, where
 * `missing` counts the rules under it on a path where nothing is
 * (ruleMissing). Labels are relative to the node above; the full path stays
 * in the tooltip.
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
  const lost = (n) => n.entries.filter(ruleMissing).length + [...n.kids.values()].reduce((k, c) => k + lost(c), 0);
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
    return [{ kind: 'folder', label: rel(n.path, base), full: n.path, pattern: /[*?[]/.test(n.path), count: count(n), missing: lost(n), children: below(n, n.path) }];
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
      // A rule on nothing inside is said here too, so a fold never hides it
      // (§4.25f *A rule on nothing says so*).
      el('span', { class: 'dim', text: (node.pattern ? 'every folder that matches, ' : '') + n(node.count, 'rule', 'rules')
        + (node.missing ? ', ' + node.missing + ' on a path where nothing is' : '') }));
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
    if (node.kind === 'folder') {
      kept.count = foundCount(children);
      kept.missing = foundCount(children, ruleMissing);
    }
    out.push(kept);
  }
  return out;
}
/** The rules found under `nodes`, or only those `only` keeps. */
function foundCount(nodes, only) {
  return nodes.reduce((k, x) => k + (x.kind === 'rule' && !x.context && (!only || only(x.row)) ? 1 : 0) + foundCount(x.children, only), 0);
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
  if (r.modeNote) subj.append(el('div', { class: 'dim rule-mode-note', text: r.modeNote }));
  subj.title = r.title || r.subject;
  if (r.warning) subj.append(el('div', { class: 'rule-warn', role: 'note' }, warningWords(r)));
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

/** Under the row of a rule (and its opened detail), the question a change that
 *  makes protection weaker asks (changeRule), while it asks: Remove anyway
 *  or Allow anyway posts the change with `expected` from the server; Cancel
 *  gives the focus back to the ⋯ of the row. */
function ruleAsk(r) {
  const key = ruleRowKey(r);
  const data = asking('rule:' + key);
  if (!data) return null;
  const what = data.action === 'remove' ? 'Removing this rule' : data.action === 'allow' ? 'Always allowing this' : 'This change';
  const yes = data.action === 'remove' ? 'Remove anyway' : data.action === 'allow' ? 'Allow anyway' : 'Change anyway';
  const box = askBox('rule:' + key, [what + ' makes protection weaker for ', el('code', { text: data.rule.subject }), '.'], yes,
    (at, d) => changeRule(d.rule, d.action, at, d),
    () => {
      renderRules();
      const row = ruleRowAt(key, false);
      const more = row && row.querySelector('.file-more');
      if (more) more.focus();
    }, true);
  box.setAttribute('role', 'listitem');
  return box;
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

/** The effect of a rule, and under it, for a rule with an end still to
 *  come, the line "until Dec 1, 09:00" (§4.25u, *A rule with an end date
 *  says when*), so the row reads "Always allowed until Dec 1, 09:00". */
function effectCell(r, row) {
  const cell = effectWords(r, row);
  if (!r.until) return cell;
  return el('div', { class: 'rule-effect' }, cell, el('div', { class: 'dim rule-until' }, 'until ', momentNode(r.until)));
}
/** "until Dec 1, 09:00", as the row draws it, for Find. */
function untilWords(iso) {
  const ms = Date.parse(iso);
  return 'until ' + (Number.isFinite(ms) ? clockWords(ms) : iso);
}
/** The effect of a rule: a menu when it can be turned around, else words. */
function effectWords(r, row) {
  const cls = r.effectClass === 'ok' ? 'allow' : r.effectClass === 'bad' ? 'block' : 'none';
  if (r.flip) {
    const sel = el('select', { class: 'effect-select', 'aria-label': 'What happens for ' + r.subject });
    sel.append(el('option', { value: '', text: r.effect }), el('option', { value: 'flip', text: r.flip.text }));
    deliberateMenu(sel, row, 'rule:' + ruleRowKey(r), '', async () => {
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

/** The use line of an opened rule (dashboard.md §4.25p): how often it
 *  decided something and, when the arbiter keeps the moment, when it last
 *  did, "12 uses, the last 3 hours ago" or "1 use, 3 hours ago", so a rule
 *  still at work reads apart from one last used months ago before Remove.
 *  Never used, an answer or a label saved here: the words alone. */
function useLine(r) {
  if (!Number.isFinite(r.lastHit)) return [r.used];
  return [r.used + (r.hits === 1 ? ', ' : ', the last '), agoNode(r.lastHit)];
}

/** Under an opened rule: when and where it was made, how often it was used,
 *  its policy.yaml lines, and Remove. Each button names its row, its own
 *  words first (dashboard.md §4.25 *A label chosen in Your rules keeps the
 *  focus*): "Remove the rule for b.example", "Show in policy.yaml: b.example". */
function ruleDetail(r) {
  const box = el('div', { class: 'rule-detail', role: 'listitem', 'aria-label': 'About ' + r.subject });
  if (r.asked) box.append(askedLine(r.asked));
  if (r.modeNote) box.append(el('div', { class: 'dim rule-mode-note', text: r.modeNote }));
  // A rule with an end: the row words again, and how long is left.
  if (r.until) {
    const ms = Date.parse(r.until);
    box.append(el('div', { class: 'rule-ends' }, r.effect + ' until ', momentNode(r.until), Number.isFinite(ms) ? ', ' + endsIn(ms) + '.' : '.'));
  }
  if (r.origin) box.append(originLine(r.origin, r.subject, changeFindTerm(r)));
  if (r.used) box.append(el('div', { class: 'dim' }, ...useLine(r)));
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

/** What an opened rule's *Find its changes* searches Rule changes for
 *  (§4.25 *Finding a rule change*): the name a change row gives it. A file:
 *  its `~/…` path. A send rule to one host: that host, as the row and the
 *  change row both write it. A connection: its host alone, since a change
 *  made without a port names none (`pypi.org`) while the row shows the port
 *  it got (`pypi.org:443`), and the search matches words. Nothing where no
 *  one name is right: anywhere / any address, several hosts, a program, a
 *  built-in protection, a source. */
function changeFindTerm(r) {
  if (r.group === 'files') return r.path ? shortPath(r.path) : null;
  const id = String(r.sourceId || '');
  if (id.startsWith('app:')) return null;
  if (r.ruleKind === 'connect-allow') {
    const m = /^connect:[a-z]+:(.+):[^:]+$/.exec(id);
    return m && m[1] !== '*' ? m[1] : null;
  }
  if (typeof r.ruleKind === 'string' && r.ruleKind.startsWith('release-')) {
    const to = String(r.title || '');
    return to && to !== '*' && to !== 'anywhere' && !/[,\s]/.test(to) ? to : null;
  }
  return null;
}

/** Who put a rules-file row there (§4.25i): the newest recorded change that
 *  wrote it; "no record" only when the record was read whole; else nothing. */
function ruleOrigin(id) {
  const o = S.origins;
  if (!o) return null;
  return Object.prototype.hasOwnProperty.call(o.origins, id) ? o.origins[id] : o.complete ? o.unrecorded : null;
}

/** The origin line under a rules-file row. A recorded change ends it with a
 *  link to that change in Approvals, at its Rule changes row with its Undo
 *  (`/approvals/<pc-…>`, markApprovalsAsk), named by the rule `subject`.
 *  The line of a file, send or connection rule (`find`: changeFindTerm,
 *  its name as a change row gives it) has a second, to Rule changes searched
 *  for that name (§4.25 *Finding a rule change*, `data-land` "changes:<words>"). */
function originLine(o, subject, find = null) {
  const line = el('div', { class: 'dim rule-origin' });
  const at = whenNode(o.at);
  // The agent that made or asked for the change, by name, and its folder
  // after the moment, when Home lists its session (§4.25 *A rule change and
  // the agent that asked*): "Claude Code added this. …, Oct 21, 16:31 ·
  // from Claude Code in ~/projects/shop."
  const asker = changeAsker(o);
  if (o.who) ORIGIN_DRAWN.set(line, { o, subject, find, key: JSON.stringify(asker) });
  line.append(namedSentence(o, asker), at ? ', ' : '', at || '', (at && changeFrom(asker)) || '', '.');
  // A later edit Mandu did not see happen (made while it was not running).
  if (o.changedSince) line.append(' It was changed in policy.yaml after that, while Mandu was not running.');
  if (o.session) line.append(' ', askLink(o.session, null));
  if (o.recorded && typeof o.changeId === 'string' && RULE_CHANGE_ID.test(o.changeId)) {
    const text = 'See this change in Approvals';
    line.append(o.session ? ' · ' : ' ', el('a', {
      href: routeHref('approvals', o.changeId), 'data-page-link': 'approvals', 'data-ask': o.changeId,
      class: 'change-link', text, 'aria-label': rowControlName(text, subject),
    }));
    const q = find ? historyQuery(find) : '';
    if (q) {
      const words = 'Find its changes';
      line.append(' · ', el('a', {
        href: routeHref('approvals') + '?changes=' + enc(q) + '#rule-changes', 'data-page-link': 'approvals', 'data-land': 'changes:' + q,
        class: 'change-find-link', text: words, 'aria-label': rowControlName(words, subject),
      }));
    }
  }
  return line;
}

/** The origin lines drawn of an agent's change, with what each was drawn
 *  from and the agent it named (renameOriginLines). */
const ORIGIN_DRAWN = new WeakMap();

/** The Rules page is not drawn again by Home's poll: an origin line drawn
 *  before Home listed its session (or after it left) is drawn again with
 *  the agent Home knows now, a focus on one of its links kept on it. */
function renameOriginLines() {
  for (const line of document.querySelectorAll('.rule-origin')) {
    const was = ORIGIN_DRAWN.get(line);
    if (!was || JSON.stringify(changeAsker(was.o)) === was.key) continue;
    const focused = line.contains(document.activeElement) ? document.activeElement.className : null;
    const next = originLine(was.o, was.subject, was.find);
    line.replaceWith(next);
    const again = focused ? [...next.querySelectorAll('a')].find((a) => a.className === focused) : null;
    if (again) again.focus({ preventScroll: true });
  }
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

/** A menu that saves at once waits for Enter from the keyboard (dashboard.md
 *  §4.25 *A menu that saves at once waits for Enter from the keyboard*):
 *  Your rules' effect menu and a prompt filter's action. Chromium on Linux
 *  and Windows (and Firefox) pick the next option on an arrow key on a
 *  closed menu and fire `change` at once, so until 2026-10-23 one Down arrow
 *  on a past answer's "Always blocked" let that send go. A choice made with
 *  a browsing key (an arrow, Home, End, Page Up or Down, a typed letter) is
 *  shown with a line under the row, `role="status"` and describing the menu:
 *  Enter makes it (`act`, what a click runs), Escape or leaving the menu
 *  puts back the choice in force (`current`). A pick with the pointer, or
 *  from the opened list (any other key clears the mark), acts at once, as
 *  before. A wrong mark only asks for an Enter, never saves. A choice that
 *  waits is kept by the row's key with the choice in force it was made
 *  against, so a list drawn again meanwhile shows it again. */
const MENU_BROWSE_KEYS = new Set(['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', 'Home', 'End', 'PageUp', 'PageDown']);
const MENU_WAITS = new Map();
let menuWaitSeq = 0;
function deliberateMenu(sel, row, key, current, act) {
  let keyed = false;
  let line = null;
  const described = sel.getAttribute('aria-describedby');
  const wordsOf = (v) => { const o = [...sel.options].find((x) => x.value === v); return o ? o.textContent : v; };
  const settle = () => {
    MENU_WAITS.delete(key);
    if (line) { line.remove(); line = null; }
    if (described) sel.setAttribute('aria-describedby', described);
    else sel.removeAttribute('aria-describedby');
  };
  const wait = () => {
    MENU_WAITS.set(key, { value: sel.value, current });
    if (!line) { line = el('div', { class: 'dim menu-wait', role: 'status', id: 'menu-wait-' + (++menuWaitSeq) }); row.append(line); }
    line.textContent = 'Press Enter to change it to ' + wordsOf(sel.value) + ', or Escape to keep ' + wordsOf(current) + '.';
    sel.setAttribute('aria-describedby', line.id);
  };
  const keep = () => { settle(); sel.value = current; };
  sel.addEventListener('keydown', (e) => {
    if (line && e.key === 'Enter' && !e.isComposing) { e.preventDefault(); keyed = false; settle(); act(); return; }
    if (line && plainEscape(e)) { e.preventDefault(); keyed = false; keep(); return; }
    keyed = !(e.altKey || e.ctrlKey || e.metaKey) && (MENU_BROWSE_KEYS.has(e.key) || (e.key.length === 1 && e.key !== ' '));
  });
  for (const type of ['pointerdown', 'mousedown']) sel.addEventListener(type, () => { keyed = false; });
  sel.addEventListener('change', () => {
    if (!keyed) { settle(); act(); return; }
    keyed = false;
    if (sel.value === current) settle();
    else wait();
  });
  // Leaving the menu, a tick later: a list drawn again meanwhile took the
  // menu off the page, and its new menu shows the choice instead.
  sel.addEventListener('blur', () => {
    if (!line) return;
    setTimeout(() => { if (line && sel.isConnected && document.activeElement !== sel) keep(); }, 0);
  });
  const was = MENU_WAITS.get(key);
  if (!was) return;
  if (was.current !== current || ![...sel.options].some((o) => o.value === was.value)) { MENU_WAITS.delete(key); return; }
  sel.value = was.value;
  // Once the row is whole, so the line comes last in it.
  queueMicrotask(() => { if (sel.value === was.value && !line) wait(); });
}

/** A notice's words, and its Undo (Your rules' and each Settings card's).
 *  A notice stays until its card's next change, so a model removed and
 *  then a label saved leave two; until 2026-10-11 both buttons read "Undo",
 *  with no word of what each undoes. Its Undo is named by its card, its own
 *  word first, and described by the notice's words (dashboard.md §4.25 *A
 *  notice's Undo says which change it undoes*). */
function noticeWords(box, text) { return el('span', { id: box.id + '-words' }, ...(Array.isArray(text) ? text : [words(text)])); }
/** `label`: the words of the button when "Undo" alone would not say which
 *  part of the notice it takes back ("Undo the 4 changes"). */
function noticeUndo(box, card, onclick, label) {
  const text = label || 'Undo';
  return el('button', { type: 'button', class: 'btn small', text, 'aria-label': text + (label ? ' in ' : ' the change in ') + card, 'aria-describedby': box.id + '-words', onclick });
}
/** A link to the change `changeId` in Approvals, at its Rule changes row,
 *  marked, with its Undo (`/approvals/<pc-…>`, markApprovalsAsk); null for
 *  an id of another shape. */
function changesLink(changeId, text) {
  if (typeof changeId !== 'string' || !RULE_CHANGE_ID.test(changeId)) return null;
  return el('a', { href: routeHref('approvals', changeId), 'data-page-link': 'approvals', 'data-ask': changeId, class: 'change-link', text });
}
/** After the Undo of a Settings card notice: See it in Approvals, the link
 *  to that change at its Rule changes row (changesLink), named by its card
 *  as the Undo is and described by the notice words (dashboard.md §4.25
 *  *and on Settings*). Nothing for an id of another shape. */
function noticeChangeLink(box, card, changeId) {
  const link = changesLink(changeId, 'See it in Approvals');
  if (!link) return;
  link.setAttribute('aria-label', rowControlName(link.textContent, 'the change in ' + card));
  link.setAttribute('aria-describedby', box.id + '-words');
  box.append(link);
}

/** What Discard threw away, while its notice still offers Undo
 *  (dashboard.md §4.25n *Discard can be undone*): `{ pending, skipped }`,
 *  the entries of F.pending as they were and the ids of the suggestions
 *  Discard itself skipped (after a Drop, its one entry and `at`, its
 *  place: dropNotice). Page-side only: kept in no storage, so a reload
 *  drops it. Anything else written into the notice (rulesNotice) or a new
 *  change added to the bar (dropDiscardUndo) drops it too. */
let DISCARDED = null;

/** Show what just changed above the list, with Undo when the change has one.
 *  `text`: words, or a list of parts (a link among them). `undoLabel`: the
 *  words of its Undo (noticeUndo). Undo keeps the keyboard focus in Your rules
 *  (settingsPlace): its button gone, the block's heading. */
function rulesNotice(text, changeId, undoLabel) {
  const box = document.getElementById('rules-notice');
  DISCARDED = null;
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
    }, undoLabel));
  }
}

/** A question asked on the page, in the row or box it was pressed in
 *  (dashboard.md §4.25n *Rules asks on the page, not in a browser
 *  dialog*): Remove or Allow instead on a rule when the server says it makes
 *  protection weaker, Move them into policy.yaml, and Not a secret; in
 *  Settings, a change to Models, Sensitivity labels or Prompt filters the
 *  server says loosens protection (settingsAsk); and Let it through under a
 *  message you wrote (letAsk). Until 2026-10-25 (Settings and Let it
 *  through: 2026-10-26) each asked in window.confirm, which a browser told
 *  to stop showing dialogs answers "no" at once, unseen: the button did
 *  nothing. The page calls window.confirm nowhere now.
 *  One question at a time, `{ key, data }`: which place asks, and what its
 *  answer needs (`expected` from the server, where the focus was at the press,
 *  `busy` while its request is out). Kept by its key, so a list drawn again
 *  (Find, a read of the rules, the poll of a scan) draws the question again. */
let ASKING = null;
function askInPlace(key, data) { ASKING = { key, data }; }
function asking(key) { return ASKING && ASKING.key === key ? ASKING.data : null; }
/** The box of the question `key` asks, for its place to draw; null while it
 *  asks none. Its sentence (`words`: words, or a list of words and nodes),
 *  which takes the focus: a line, never the button, so a second Enter on
 *  what asked does nothing. Under it, `more` (nodes, such as the list of
 *  what a Settings change opens and its warnings: confirmParts). Then the
 *  button that does it (`yes`, its words: `onYes(box, data)`) and Cancel;
 *  Escape in the box is Cancel, which ends the question and calls `back()`
 *  to draw the place again and give the focus back to what asked. An
 *  Escape the box takes is not also the Escape of a form around it (the
 *  Models form's Cancel). `weaker`: drawn as the warning it is. */
function askBox(key, words, yes, onYes, back, weaker, more) {
  const data = asking(key);
  if (!data) return null;
  const box = el('div', { class: 'ask-in-place' + (weaker ? ' weaker' : ''), 'data-asking': key });
  const said = el('p', { class: 'ask-in-place-words', tabindex: '-1' }, ...(Array.isArray(words) ? words : [words]));
  const cancel = () => {
    if (asking(key) !== data || data.busy) return;
    ASKING = null;
    back();
  };
  box.append(said);
  if (more && more.length) box.append(el('div', { class: 'ask-in-place-more' }, ...more));
  box.append(el('div', { class: 'ask-in-place-buttons' },
    el('button', { type: 'button', class: 'btn small ask-in-place-yes', text: yes, onclick: () => { if (asking(key) === data && !data.busy) onYes(box, data); } }),
    el('button', { type: 'button', class: 'btn small', text: 'Cancel', onclick: cancel })));
  box.addEventListener('keydown', (e) => {
    if (!plainEscape(e)) return;
    e.preventDefault();
    cancel();
  });
  if (data.busy) busyRow(box, true);
  return box;
}
/** The question drawn under `root`, its sentence given the focus, only
 *  when the focus was at the place that asked at the press (`place`, taken
 *  by settingsPlace or pollPlace, null when the focus was elsewhere or
 *  nowhere): a focus elsewhere stays where it is. */
function focusAsk(root, place) {
  const words = place !== null && root ? root.querySelector('.ask-in-place-words') : null;
  if (words) focusThere(words);
}
/** Where the focus is in the box of the question before a draw takes the
 *  box away: an empty string for its sentence, the words of a button, or
 *  null (not in it); then, once drawn again and only if the focus fell, the
 *  same part of the new box (askRefocus). */
function askHeld() {
  const a = document.activeElement;
  const box = a && a.closest ? a.closest('.ask-in-place') : null;
  if (!box) return null;
  return a.classList.contains('ask-in-place-words') ? '' : a.textContent;
}
function askRefocus(held) {
  if (held === null || !focusFell()) return;
  const box = document.querySelector('.ask-in-place');
  if (!box) return;
  if (held === '') { focusThere(box.querySelector('.ask-in-place-words')); return; }
  const b = [...box.querySelectorAll('button')].find((x) => x.textContent === held && !x.disabled);
  if (b) b.focus({ preventScroll: true });
}

/** Ask `key` now (askInPlace), in a place drawn once and not again for the
 *  question (a Settings row, a form, the row of a note): any other box
 *  drawn goes, as one question is asked at a time; `draw()` makes the box
 *  and `put(box)` puts it in its place. Its sentence takes the focus when
 *  the focus was at the place that asked (`data.place`, settingsPlace's,
 *  not null), as focusAsk does. */
function askNow(key, data, draw, put) {
  askInPlace(key, data);
  for (const b of document.querySelectorAll('.ask-in-place')) b.remove();
  const box = draw();
  if (!box) return;
  put(box);
  if (data.place !== null) focusThere(box.querySelector('.ask-in-place-words'));
}
/** The question `key` ends without an answer to give (its change went out,
 *  or a new press in its place asks anew): only that question (`data`, when
 *  given), and its box goes from the page. */
function dropAsk(key, data) {
  if (ASKING && ASKING.key === key && (!data || ASKING.data === data)) ASKING = null;
  for (const b of document.querySelectorAll('.ask-in-place')) if (b.dataset.asking === key) b.remove();
}
/** After Cancel: the focus back on the button or menu that asked (`opener`,
 *  a selector) in `place`, the row or form drawn now. */
function askOpener(place, opener) {
  const b = place && place.querySelector(opener);
  if (b && reachable(b)) b.focus({ preventScroll: true });
}

/** The row of Your rules drawn for rule `id`, and its opened detail (where
 *  Remove is) when `detail` and it is open. */
function ruleRowAt(id, detail) {
  const row = [...document.querySelectorAll('#rules-list .row[data-rule]')].find((x) => x.getAttribute('data-rule') === id);
  const next = row && row.nextElementSibling;
  return detail && next && next.classList.contains('rule-detail') ? next : row || null;
}

/** A rule from your rules: remove it or flip it, here. The server plans the
 *  edit from the row; a change that loosens protection comes back asking
 *  for a confirmation, asked under the row (askBox) and sent back as
 *  `expected` with "Remove anyway" or "Allow anyway" (`asked`: the data of
 *  that question). The keyboard focus stays in Your rules as in a Settings
 *  card (settingsPlace): the row's menu, drawn again with its new effect;
 *  the block's heading once the row is gone; the menu or button pressed,
 *  described, after a refusal; the ⋯ of the row after Cancel. */
async function changeRule(rule, action, row, asked) {
  const place = asked ? asked.place : settingsPlace(row);
  busyRow(row, true);
  const body = { id: rule.id, action };
  if (asked) asked.busy = true;
  const r = await apiPost('policy/rules/change', asked ? { ...body, expected: asked.expected } : body);
  if (!asked && r.ok && r.data && r.data.confirm) {
    askInPlace('rule:' + rule.id, { rule, action, expected: r.data.expected, place });
    renderRules();
    focusAsk(document.getElementById('rules-list'), place);
    return;
  }
  if (asked) {
    asked.busy = false;
    if (asking('rule:' + rule.id) === asked) ASKING = null;
  }
  if (!r.ok || !r.data || !r.data.applied) {
    // Asked first: the question goes, and the words show on the row, as
    // they did before it was asked on the page.
    if (asked) { renderRules(); row = ruleRowAt(rule.id, action === 'remove') || row; }
    showAskError(row, changeRefusal(r, 'Not changed', 'could not change the rule (' + r.status + ')'));
    settingsRefocus(place, row);
    return;
  }
  RULES_READS.wrote();
  rulesNotice(action === 'remove' ? 'Rule removed.' : action === 'allow' ? 'Now always allowed.' : 'Now always blocked.', r.data.changeId);
  await loadRules();
  settingsRefocus(place);
}

/** An answer on Rules by what the arbiter keeps it as (its row field
 *  `allowKeptAs`, policy-panel.ts): for this session on a send of a
 *  program keyed to one, once on one run of a program or a send keyed to none (a
 *  Block there is kept once too), else Always. */
function answerEffectWords(approved, keptAs) {
  if (keptAs === 'session') return approved ? 'Allowed for this session' : 'Blocked for this session';
  if (keptAs === 'once') return approved ? 'Allowed once' : 'Blocked once';
  return approved ? 'Always allowed' : 'Always blocked';
}

/** The notice after an answer is changed on Rules, in the words of its flip
 *  (answerEffectWords). A once answer leaves Rules, which lists standing
 *  answers only: the notice says where it is listed and links its row. */
function answerAgainNotice(id, approve, keptAs) {
  if (keptAs === 'session') return approve ? 'Now allowed for this session.' : 'Now blocked for this session.';
  if (keptAs !== 'once') return approve ? 'Now always allowed.' : 'Now always blocked.';
  return [(approve ? 'Now allowed once: your agent\'s next try goes through' : 'Now blocked once: your agent\'s next try is stopped') + ', then Mandu asks again. It is listed under ', askRowLink(id, 'Approvals › Answered earlier'), '.'];
}

async function answerAgain(id, approve, row, message = false, keptAs = null) {
  const place = settingsPlace(row);
  busyRow(row, true);
  const r = await apiPost('egress/approvals/' + encodeURIComponent(id) + '/' + (approve ? 'approve' : 'deny'));
  if (!r.ok) { showAskError(row, refusalText(r, 'could not change the answer (' + r.status + ')')); settingsRefocus(place, row); return; }
  RULES_READS.wrote();
  // A session's answer to a held message says what goes to the AI (§4.25u).
  rulesNotice(message ? (approve ? 'Now sent as written for that session.' : 'Now sent masked for that session.') : answerAgainNotice(id, approve, keptAs), null);
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
// An empty tab with the page's rules unread claims only what was read
// (§4.25aa *An empty list that could not read every rule says so*).
const BY_WHO_EMPTY_PARTIAL = 'No rule in policy.yaml makes a file secret. The rules made on this page could not be read, so they are not listed here.';

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
  const empty = !t.rows.length;
  if (empty) list.append(el('div', { class: 'empty', text: v.partial ? BY_WHO_EMPTY_PARTIAL : BY_WHO_EMPTY }));
  else list.append(el('div', { class: 'table by-who-rows', role: 'list' }, ...t.rows.map((r) => byWhoRow(r, tab))));
  const note = document.getElementById('by-who-note');
  // The empty line already says what could not be read; the note does not repeat it.
  note.textContent = [v.partial && !empty ? BY_WHO_PARTIAL : '', t.note || ''].filter(Boolean).join(' ');
  wireHostCheck();
  // Its file buttons follow Your rules as drawn now.
  drawHostCheck(HC.state);
}

/** One program, host or AI: its name (a long one cut as longName cuts
 *  it), and each list of files under a coloured mark saying what it may do
 *  with them; under a program's or your own AI's lists, the line counting
 *  the files it gets as the row it is compared with does (`rest`, §4.25aa
 *  *Only what differs*). */
function byWhoRow(r, tab) {
  const plain = r.kind === 'any' || tab === 'models';
  const name = el('div', { class: 'by-who-name' },
    plain ? el('strong', { text: r.name }) : longName(el('code', { class: 'by-who-subject', text: r.name })),
    r.about ? el('p', { class: 'by-who-about' }, textParts(r.aboutParts, r.about)) : null);
  const groups = el('div', { class: 'by-who-groups' });
  for (const g of r.groups) {
    const items = el('ul', { class: 'by-who-items' });
    for (const it of g.items) {
      // "~/.ssh and everything inside (checked by Mandu)", as the Opens it line words a program.
      // A rule on a path where nothing is says so after it, as its row
      // under Your rules does (§4.25aa *A rule on nothing*).
      const lost = missingRule(it.rule);
      const more = [it.reach, it.how ? '(' + it.how + ')' : null, lost ? '(' + BY_WHO_MISSING + ')' : null].filter(Boolean).join(' ');
      const chip = longName(el('code', { text: it.path }));
      // A file whose rule has a row in the tree drawn now opens it; any
      // other stays plain code, so nothing points to a row that is not there.
      const file = treeRule(it.rule) ? el('button', {
        type: 'button', class: 'link-btn by-who-link', 'aria-label': ruleLinkLabel(it.path, lost),
        onclick: () => openRuleRow(it.rule),
      }, chip) : chip;
      items.append(el('li', null, file, more ? el('span', { class: 'by-who-more', text: ' ' + more }) : null));
    }
    groups.append(el('div', { class: 'by-who-group' },
      el('span', { class: 'by-who-label' }, el('span', { class: 'dot ' + (g.tone || 'bad'), 'aria-hidden': 'true' }), g.label),
      items));
  }
  if (r.rest) groups.append(el('p', { class: 'by-who-none by-who-rest', text: r.rest }));
  else if (!r.groups.length) groups.append(el('span', { class: 'by-who-none', text: 'Nothing under your rules.' }));
  return el('div', { class: 'row by-who-row' + (r.kind === 'any' ? ' any' : ''), role: 'listitem' }, name, groups);
}

/** The row of Your rules for a rule's own path (a by-who item's `rule`), or
 *  null. policy.yaml's comes first, as the by-who read keeps it. */
function treeRule(path) {
  return (typeof path === 'string' && F.rules.find((r) => r.path === path)) || null;
}

/** Whether a by-who file's rule names a path where nothing is: its row
 *  under Your rules says so (ruleMissing, so never a pattern). A rule with no
 *  row there is not known to be, so it is never marked. */
const BY_WHO_MISSING = 'nothing at this path';
function missingRule(path) {
  const r = treeRule(path);
  return !!r && ruleMissing(r);
}

/** A by-who or Check a host file button's name. */
function ruleLinkLabel(name, lost) {
  return 'Show the rule for ' + name + ' in Your rules' + (lost ? ' (' + BY_WHO_MISSING + ')' : '');
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

// ── Files made from your secrets (dashboard.md §4.25aa *Files made from your secrets*)
// The files Mandu labelled on its own because what wrote them held a secret
// (confidentiality.md §8), as /api/secrets sends them (panel.derived). Read
// only: each opens in Add a rule, where a rule of yours for the file comes
// first. Closed until Show; MADE_FROM_PAGE entries, then Show more. Three or
// more files in one folder are one entry, a folder row (madeFromFolderRow).
const MADE_FROM_PAGE = 20;
const MADE_FROM_FOLD = 3;
// `folders`: the open folder rows, each with how many of its files show.
const MF = { open: false, shown: MADE_FROM_PAGE, folders: new Map() };
// A key a session's page can be opened by: never `proc:…` (a program the
// guard saw) nor `guard` (a copy the guard followed), which name no session.
const MADE_FROM_SESSION_RE = /^[A-Za-z0-9._@-][A-Za-z0-9._:@-]{0,199}$/;

function madeFromSession(key) {
  return typeof key === 'string' && key !== 'guard' && !key.startsWith('proc:') && MADE_FROM_SESSION_RE.test(key) ? key : null;
}

/** What wrote a file, in words, never its raw key: a program that held a
 *  secret (`process`), a copy or move the guard followed, else the AI. The
 *  card's rows and Add a rule's line both say these (writerLine). */
function writerWords(d) {
  if (d.tool === 'process') return 'written by a program that held a secret';
  if (d.tool === 'identity' || d.tool === 'link') return 'copied from a secret file';
  if (d.tool === 'rename') return 'moved from a secret file';
  const tool = typeof d.tool === 'string' && d.tool !== '' && d.tool !== '?' ? d.tool : null;
  return tool ? 'written by the AI\'s ' + tool : 'written by the AI';
}

/** The record of the card for a file, by its absolute path, or null: none
 *  read yet, a failed read, an older server with no list. */
function madeFromRecord(path) {
  return (typeof path === 'string' && madeFromRows().find((d) => d.path === path)) || null;
}

/** Where a label comes from, in Add a rule's words. A file made from a
 *  secret says what wrote it as its row in the card does ("Written by a
 *  program that held a secret"); with no row, the label's own sentence,
 *  true of every writer. */
function labelFrom(label, path) {
  if (!label) return '';
  const d = label.source === 'written' ? madeFromRecord(path) : null;
  if (!d) return label.from || '';
  const w = writerWords(d);
  return w.charAt(0).toUpperCase() + w.slice(1);
}

/** After that line, the way to the file's row in the card, or null. */
function madeFromLink(label, path) {
  if (!label || label.source !== 'written' || !madeFromRecord(path)) return null;
  return el('button', { type: 'button', class: 'link-btn made-from-see', text: 'See it in Files made from your secrets',
    onclick: () => showMadeFromRow(path) });
}

/** See it in Files made from your secrets, pressed: the card opens, with
 *  as many pages as reach the file's row, its folder row opened with as
 *  many of its pages, and the focus goes to the row's Change who may read
 *  it. */
function showMadeFromRow(path) {
  const pages = (at) => Math.ceil((at + 1) / MADE_FROM_PAGE) * MADE_FROM_PAGE;
  const entries = madeFromEntries(madeFromRows());
  const at = entries.findIndex((e) => (e.folder ? e.files.some((d) => d.path === path) : e.file.path === path));
  if (at >= MF.shown) MF.shown = pages(at);
  const folder = at >= 0 ? entries[at] : null;
  if (folder && folder.folder) {
    const inside = folder.files.findIndex((d) => d.path === path);
    MF.folders.set(folder.folder, Math.max(MF.folders.get(folder.folder) || MADE_FROM_PAGE, pages(inside)));
  }
  setMadeFromOpen(true);
  // Compared as values, never spliced into a selector: paths are server data.
  const row = [...document.querySelectorAll('#made-from-list .made-from-row')].find((r) => r.getAttribute('data-path') === path);
  const to = row ? row.querySelector('.made-from-change') : document.getElementById('made-from-open');
  if (!to) return;
  if (to.scrollIntoView) to.scrollIntoView({ block: 'nearest' });
  to.focus();
}

/** The card's files as /api/secrets sent them (panel.derived), [] when an
 *  older server sends no such list or the read failed; newest first. */
function madeFromRows() {
  const panel = S.secrets && S.secrets.panel;
  return panel && Array.isArray(panel.derived) ? panel.derived.filter((d) => d && typeof d.path === 'string' && d.path) : [];
}
function madeFromSorted(rows) {
  return [...rows].sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
}
/** The card's entries, newest first: a file, or `{ folder, files }` for
 *  MADE_FROM_FOLD or more files in one direct parent (`/home/u/dist/`, up
 *  to the last slash), placed at its newest file. `dist/` and
 *  `dist/assets/` are two folders. */
function madeFromEntries(rows) {
  const sorted = madeFromSorted(rows);
  const parentOf = (p) => p.slice(0, p.lastIndexOf('/') + 1);
  const byParent = new Map();
  for (const d of sorted) {
    const at = parentOf(d.path);
    if (at) byParent.set(at, [...(byParent.get(at) || []), d]);
  }
  const entries = [];
  const placed = new Set();
  for (const d of sorted) {
    const at = parentOf(d.path);
    const files = at ? byParent.get(at) : null;
    if (!files || files.length < MADE_FROM_FOLD) entries.push({ file: d });
    else if (!placed.has(at)) { placed.add(at); entries.push({ folder: at, files }); }
  }
  return entries;
}

function setMadeFromOpen(open) {
  MF.open = open;
  renderMadeFromSecrets();
}

function renderMadeFromSecrets() {
  const block = document.getElementById('made-from-block');
  const rows = madeFromRows();
  // None, or an older server with no such list: no card, and no link to it.
  block.hidden = rows.length === 0;
  followSectionLinks();
  if (!rows.length) return;
  document.getElementById('made-from-count').textContent = '(' + rows.length + ')';
  const btn = document.getElementById('made-from-open');
  if (!btn.dataset.wired) {
    btn.dataset.wired = '1';
    btn.addEventListener('click', () => setMadeFromOpen(!MF.open));
  }
  btn.setAttribute('aria-expanded', MF.open ? 'true' : 'false');
  btn.textContent = MF.open ? 'Hide' : 'Show';
  document.getElementById('made-from-view').hidden = !MF.open;
  const list = document.getElementById('made-from-list');
  const more = document.getElementById('made-from-more');
  // Each Rules read draws the list again: a focus in it goes back to the
  // same control (a folder's Show, a file's link, a folder's Show more).
  const focused = madeFromFocused(list);
  clear(list); clear(more);
  if (!MF.open) return;
  const entries = madeFromEntries(rows);
  const shown = entries.slice(0, MF.shown);
  list.append(...shown.map((e, i) => (e.folder ? madeFromFolderRow(e, i) : madeFromRow(e.file))));
  const left = entries.slice(shown.length).reduce((k, e) => k + (e.folder ? e.files.length : 1), 0);
  if (left > 0) {
    more.append(moreLine('made-from-more-line', [n(left, 'more file', 'more files') + '.'], () => {
      const first = MF.shown;
      MF.shown += MADE_FROM_PAGE;
      renderMadeFromSecrets();
      const row = list.children[first];
      const to = row && row.querySelector(row.classList.contains('made-from-folder') ? '.made-from-folder-open' : '.made-from-change');
      if (to) to.focus();
    }));
  }
  if (focused) madeFromRefocus(list, focused);
}

/** The control of the list that has the focus, by what it names, or null. */
function madeFromFocused(list) {
  const a = document.activeElement;
  if (!a || !list.contains(a)) return null;
  const folder = a.closest('.made-from-folder');
  if (a.classList.contains('made-from-folder-open')) return { folderOpen: folder.getAttribute('data-folder') };
  if (a.classList.contains('show-rest') && folder) return { folderMore: folder.getAttribute('data-folder') };
  const row = a.closest('.made-from-row');
  if (row && a.classList.contains('made-from-change')) return { change: row.getAttribute('data-path') };
  return null;
}
/** Back to that control, drawn again; compared as values, never spliced
 *  into a selector (paths are server data). Gone: the focus stays put. */
function madeFromRefocus(list, was) {
  const folder = (key) => [...list.querySelectorAll('.made-from-folder')].find((f) => f.getAttribute('data-folder') === key);
  let to = null;
  if (was.folderOpen !== undefined) to = folder(was.folderOpen)?.querySelector('.made-from-folder-open');
  else if (was.folderMore !== undefined) to = folder(was.folderMore)?.querySelector('.show-rest');
  else {
    const row = [...list.querySelectorAll('.made-from-row')].find((r) => r.getAttribute('data-path') === was.change);
    to = row && row.querySelector('.made-from-change');
  }
  if (to && document.activeElement !== to) to.focus({ preventScroll: true });
}

/** A folder's Show or Hide, pressed: the folder opens or closes, and the
 *  focus stays on its button. */
function setMadeFromFolder(folder, open) {
  if (open) MF.folders.set(folder, MADE_FROM_PAGE); else MF.folders.delete(folder);
  renderMadeFromSecrets();
  const row = [...document.querySelectorAll('#made-from-list .made-from-folder')].find((f) => f.getAttribute('data-folder') === folder);
  const btn = row && row.querySelector('.made-from-folder-open');
  if (btn) btn.focus();
}

/** One folder's files, as one row: the folder, how many, the level and
 *  what wrote them only when every file says the same, the newest file's
 *  time, and Show. Opened, its files as the card's rows, newest first,
 *  MADE_FROM_PAGE then Show more. No folder action: a rule on the folder
 *  would cover files no secret made too. */
function madeFromFolderRow(e, i) {
  const at = e.folder;
  const shown = at === '/' ? '/' : shortPath(at.slice(0, -1)) + '/';
  const same = (words) => (words.every((w) => w === words[0]) ? words[0] : null);
  const level = same(e.files.map(madeFromLevel));
  const how = same(e.files.map(writerWords));
  const when = whenNode(e.files[0].updatedAt > 0 ? e.files[0].updatedAt : NaN);
  const open = MF.folders.has(at);
  const listId = 'made-from-folder-' + i;
  const btn = el('button', { type: 'button', class: 'btn small made-from-folder-open', 'aria-expanded': open ? 'true' : 'false',
    'aria-controls': listId, 'aria-label': (open ? 'Hide' : 'Show') + ' the files in ' + shown, text: open ? 'Hide' : 'Show' });
  btn.addEventListener('click', () => setMadeFromFolder(at, !MF.folders.has(at)));
  const row = el('li', { class: 'made-from-folder', 'data-folder': at },
    el('div', { class: 'made-from-folder-head' },
      longName(el('code', { text: shown })),
      ' · ', el('span', { class: 'made-from-files' }, n(e.files.length, 'file', 'files')),
      level ? ' · ' : null, level ? el('span', { class: 'made-from-level' + (e.files[0].overridden === true ? ' overridden' : '') }, level) : null,
      how ? ' · ' : null, how ? el('span', { class: 'made-from-how' }, how) : null,
      when ? ' · ' : null, when,
      ' ', btn));
  const files = el('ul', { class: 'made-from-list made-from-folder-list', id: listId });
  files.hidden = !open;
  row.append(files);
  if (!open) return row;
  const upTo = MF.folders.get(at);
  files.append(...e.files.slice(0, upTo).map(madeFromRow));
  const left = e.files.length - Math.min(upTo, e.files.length);
  if (left > 0) {
    row.append(moreLine('made-from-folder-more-' + i, [n(left, 'more file', 'more files') + ' in ' + shown + '.'], () => {
      MF.folders.set(at, upTo + MADE_FROM_PAGE);
      renderMadeFromSecrets();
      const again = [...document.querySelectorAll('#made-from-list .made-from-folder')].find((f) => f.getAttribute('data-folder') === at);
      const to = again && again.querySelectorAll('.made-from-folder-list .made-from-change')[upTo];
      if (to) to.focus();
    }));
  }
  return row;
}

/** The level a file is kept at, or that your rule decides now. */
function madeFromLevel(d) {
  return d.overridden === true
    ? 'Your rule decides now: ' + levelText(d.effective || d.level, [])
    : levelText(d.level, []);
}

/** One file: its path, the level it is kept at (or that your rule decides
 *  now), what wrote it, when, and the link that opens it in Add a rule. */
function madeFromRow(d) {
  const shown = shortPath(d.path);
  const level = madeFromLevel(d);
  const session = madeFromSession(d.sessionKey);
  const how = el('span', { class: 'made-from-how' }, writerWords(d));
  if (session) how.append(' in ', el('a', { href: routeHref('agent', session), 'data-page-link': 'agent', 'data-session': session, class: 'made-from-session', text: 'this session' }));
  const when = whenNode(d.updatedAt > 0 ? d.updatedAt : NaN);
  return el('li', { class: 'made-from-row', 'data-path': d.path },
    longName(el('code', { text: shown })),
    ' · ', el('span', { class: 'made-from-level' + (d.overridden === true ? ' overridden' : '') }, level),
    ' · ', how,
    when ? ' · ' : null, when,
    ' · ', el('a', { href: routeHref('rules', d.path), 'data-page-link': 'rules', 'data-file': d.path, class: 'made-from-change',
      'aria-label': 'Change who may read ' + shown, text: 'Change who may read it' }));
}

// ── Check a host (dashboard.md §4.25aa *Check a host*) ─────────────────────
// A host typed under Who may get your secrets, answered from GET
// policy/host-check (the read-only whyHost of the protection service, a probe
// that queues and counts nothing): which of your secrets may go there and
// what happens to the rest, in the sentences of the server, each name as code.
// The box changes no rule. A service that cannot check a host (501) hides it.
// `waiting`: the ids of the questions waiting the last host ask was made
// with (checkHost, recheckHost: those of the Home answer then), null before.
const HC = { asked: 0, state: null, unsupported: false, drawn: null, waiting: null };

function wireHostCheck() {
  const form = document.getElementById('host-check');
  if (!form) return;
  form.hidden = HC.unsupported;
  if (form.dataset.wired) return;
  form.dataset.wired = '1';
  form.addEventListener('submit', (e) => { e.preventDefault(); checkHost(); });
}

/** Check, pressed (or Enter in the box): the focus stays where it is, in
 *  the form; only the answer under it is drawn again. */
async function checkHost() {
  const typed = document.getElementById('host-check-q').value;
  const asked = ++HC.asked;
  if (!typed.trim()) { drawHostCheck({ error: 'Type a host name, like api.example.com.' }); return; }
  askedWith(S.home);
  drawHostCheck({ loading: true });
  const r = await apiGetControl('policy/host-check?host=' + encodeURIComponent(typed.trim()));
  if (asked !== HC.asked) return;
  drawHostAnswer(r);
}

/** Each Rules read (loadRules), while an answer is drawn: the host of that
 *  answer, never the box's text, is asked again, with no "Checking…", so
 *  the box says what holds after an answer in Approvals or a Save. It takes
 *  a number as Check does: a Check pressed meanwhile wins. Drawn only when
 *  it differs (drawHostCheck); a failed one says so, as Check's does. */
async function recheckHost() {
  const c = HC.state && HC.state.check;
  if (!c || HC.unsupported) return;
  const asked = ++HC.asked;
  askedWith(S.home);
  const r = await apiGetControl('policy/host-check?host=' + encodeURIComponent(c.host));
  if (asked !== HC.asked) return;
  drawHostAnswer(r);
}

/** The questions waiting change (queue item #269): `rulesVersion` leaves
 *  them out, so a send to the drawn host that starts waiting, or one
 *  answered once in another tab or on a phone, reads no Rules. On each Home
 *  poll that answered (`asked`) while Rules is shown and the tab seen, the
 *  ids waiting are compared with those the last host ask was made with
 *  (HC.waiting); a change reads the file rows again (followFileWaiting,
 *  #284), whose read asks the drawn host itself, else asks the drawn host
 *  again (recheckHost: nothing with no answer drawn). A Rules read asked
 *  since the poll was asked (followRules, a Save) and still out
 *  (RULES_SEEN.out) asks it itself when it answers, with this answer's
 *  ids: the poll leaves it that ask. One that already answered asked with
 *  the ids of the Home answer before (queue item #303), so the poll
 *  compares as usual: at most one ask per poll, whichever answers first.
 *  A hidden tab compares nothing: the first poll after its return does. */
function followHostWaiting(asked) {
  if (S.page !== 'rules' || tabHidden()) return;
  const key = waitingKey(S.home);
  if (key === null) return;
  if (RULES_SEEN.out && RULES_SEEN.after >= asked) return;
  if (followFileWaiting(key, asked)) return;
  if (key !== HC.waiting) recheckHost();
}

/** A host ask is made now, after the Home answer `home`: the ids it says
 *  wait are those the answer has seen (HC.waiting); unknown, kept. */
function askedWith(home) {
  const key = waitingKey(home);
  if (key !== null) HC.waiting = key;
}

/** A file row's "Waiting for your answer" line follows the questions
 *  waiting (queue item #284; dashboard.md §4.25n *And the sends of it that
 *  wait*): ids that differ from those the file rows are known to be as new
 *  as (F.waitingKey: the ids of the last Home answer when a Rules read was
 *  asked, or of the first poll asked after one asked before Home answered;
 *  null before) read
 *  your rules again, as followRules does, at the version already
 *  followed, so a "Your rules changed" line shown stays and none is shown
 *  (your rules did not change), the save guard as it was. Its draw
 *  redraws Your rules and the open folder's rows (renderExplorer) and asks
 *  the drawn host again; the place and the focus are kept as a poll keeps
 *  them. While the focus is in a text field on Rules nothing is read
 *  and the ids are not taken: the first poll after it leaves reads. With no
 *  file row drawn (no file rule of yours, no folder, no typed path) there
 *  is no line: the ids are taken, nothing read. True when it began a read. */
function followFileWaiting(key, asked) {
  if (key === F.waitingKey) return false;
  // None known (the read asked before Home first answered): the first poll
  // asked after that read gives them, as it gives followRules its version.
  const first = F.waitingKey === null && asked <= RULES_SEEN.after + 1;
  if (first || (!F.rules.length && !F.data && !F.typed)) { F.waitingKey = key; return false; }
  if (rulesTyping()) return false;
  F.waitingKey = key;
  const place = pollPlace(document.getElementById('main'));
  // Null (no version given yet): a read the page asked hid the line already.
  loadRules({ version: RULES_SEEN.version }).then(() => { if (place && S.page === 'rules') pollRefocus(place); });
  return true;
}

/** The ids of the questions a Home answer says wait, as one string; null
 *  when it does not know them. */
function waitingKey(home) {
  if (!home || home.waitingKnown === false || !Array.isArray(home.waiting)) return null;
  return JSON.stringify(home.waiting.map((w) => w.id).sort());
}

function drawHostAnswer(r) {
  if (r.status === 501) {
    HC.unsupported = true;
    drawHostCheck(null);
    document.getElementById('host-check').hidden = true;
    return;
  }
  drawHostCheck(r.ok && r.data && r.data.check ? { check: r.data.check } : { error: refusalText(r, 'The host could not be checked (' + r.status + ').') });
}

/** What an answer draws: its host, its sentences and, per file, whether it
 *  is a button and marked as naming nothing (Your rules as drawn now). */
function hostCheckKey(c) {
  const files = (c.lines || []).map((l) => (l.files || []).map((f) => [!!treeRule(f.rule), missingRule(f.rule)]));
  return JSON.stringify([c.host, c.lines, files]);
}

/** The answer under the box. One that would draw as the answer on screen
 *  does is not drawn again (renderByWho at every Rules read, recheckHost):
 *  its nodes stay, the focus on them stays and the status box is quiet. */
function drawHostCheck(state) {
  HC.state = state;
  const box = document.getElementById('host-check-answer');
  if (!box) return;
  const key = state && state.check ? hostCheckKey(state.check) : null;
  if (key && key === HC.drawn && box.firstChild) return;
  HC.drawn = key;
  clear(box);
  if (!state) return;
  if (state.loading) { box.append(el('span', { class: 'dim', text: 'Checking…' })); return; }
  if (state.error) { box.append(el('p', { class: 'ask-error' }, words(state.error))); return; }
  const c = state.check;
  box.append(el('ul', { class: 'secret-lines host-check-lines', 'aria-label': 'What the rules say about ' + c.host },
    ...(c.lines || []).map(hostCheckLine)));
}

/** One sentence of the answer: its text, each name a code (a secret whose
 *  rule is drawn under Your rules a button that opens it there, as the
 *  lists above do), each link a link. */
function hostCheckLine(l) {
  const li = el('li', { 'data-kind': l.kind });
  let file = 0;
  for (const p of l.parts || []) {
    if (p.kind === 'link') { li.append(hostCheckLink(p)); continue; }
    if (p.kind !== 'code') { li.append(countWords(p.text)); continue; }
    const f = l.files && l.files[file++];
    const chip = longName(el('code', { text: p.text }));
    const lost = !!f && missingRule(f.rule);
    li.append(f && treeRule(f.rule) ? el('button', {
      type: 'button', class: 'link-btn by-who-link', 'aria-label': ruleLinkLabel(f.name, lost),
      onclick: () => openRuleRow(f.rule),
    }, chip) : chip);
    if (lost) li.append(el('span', { class: 'by-who-more', text: ' (' + BY_WHO_MISSING + ')' }));
  }
  return li;
}

/** Approvals, found by the host in Answered earlier (§4.25 *Finding an
 *  answer*) when the part names a search. */
function hostCheckLink(p) {
  if (p.q) return el('a', { href: routeHref('approvals') + '?q=' + enc(p.q), 'data-page-link': 'approvals', 'data-land': 'q:' + p.q, text: p.text });
  return el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', text: p.text });
}

/** Kept in Rules on an Answered earlier row, pressed (dashboard.md §4.25
 *  *A remembered answer opens where Rules keeps it*): Rules, at Your rules
 *  once its reads have drawn, with the row of the answer opened (showAnswerRule). */
function openAnswerRule(id) {
  return openAtCard('rules', 'rules-block', null, (card) => showAnswerRule(id, card));
}
/** Rules opened at `/rules#answer-<id>` (a new tab, a typed address): the
 *  same landing, once, as `?file=` is (landAtFile). */
function landAtAnswer(load, id) {
  focusPage();
  return landAtCard(load, 'rules-block', (card) => showAnswerRule(id, card));
}
/** The row of the answer `id` under Your rules, opened as its ⋯ opens it (Remove,
 *  its effect menu, where it was asked), scrolled into view, and returned
 *  for the focus: its ⋯. A Find a rule text that would hide it is emptied
 *  first. A row Rules no longer lists (forgotten meanwhile) says so above
 *  the list, and the heading takes the focus; so does an unread list, which
 *  says why itself. */
function showAnswerRule(id, card) {
  const heading = card && card.querySelector('h2');
  const panel = S.panel;
  if (!panel || !panel.verdictsKnown) return heading;
  const kept = (panel.queue || []).some((v) => v.id === id && v.status !== 'pending' && v.scope !== 'once');
  if (!kept) {
    const note = document.getElementById('rules-answer-note');
    note.textContent = 'That answer is no longer kept: you will be asked next time.';
    note.hidden = false;
    return heading;
  }
  const key = 'answer:' + id;
  if (findText()) clearRuleFind(false);
  S.openRule = key;
  renderRules();
  // Compared as values, never spliced into a selector: ids are server data.
  const row = [...document.querySelectorAll('#rules-list .row[data-rule]')].find((r) => r.getAttribute('data-rule') === key);
  if (!row) return heading;
  const detail = row.nextElementSibling;
  if (detail && detail.scrollIntoView) detail.scrollIntoView({ block: 'nearest' });
  if (row.scrollIntoView) row.scrollIntoView({ block: 'nearest' });
  return row.querySelector('.file-more') || row;
}
/** The note showAnswerRule leaves goes with the page. */
function hideAnswerNote() {
  const note = document.getElementById('rules-answer-note');
  if (!note) return;
  note.hidden = true;
  note.textContent = '';
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
  saving: false,       // this tab's Save is on its way (saveFileChanges)
  syncLater: false,    // another tab changed the stored lists meanwhile: read them once it answers
  syncStale: false,    // another tab changed them while this tab showed another page: Rules draws them on return
  unreadCause: false,  // the cause Your rules said it could not be read with; false: read
  noteOff: null,       // offKey() the note over unknown labels was drawn with (followFilesNote)
  answers: new Map(),  // absolute path → [{ id, host, approved }]: your standing answers about sending that file (keepFileAnswer)
  waiting: new Map(),  // absolute path → [{ id, host }]: the sends of that file that wait for your answer (keepFileWaiting)
  waitingKey: null,    // the waiting ids (waitingKey) the file rows are known to be as new as, null before (followFileWaiting)
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
/** The listing route's words for a dashboard with no protection service
 *  behind it (server/file-browser-routes.ts). */
const LABELS_NOT_CONNECTED = 'the protection service is not connected';
/** The note over a folder whose labels could not be read: a stopped
 *  protection service in the words of the page, with the link to its Start,
 *  never the socket the route could not dial; any other cause as the
 *  server wrote it. While Mandu is not running at all (offCause), a cause
 *  that tells only that no service answered (the dial, no service, no
 *  words) is no fault: the levels show once Mandu starts (dashboard.md
 *  §4.25 *Every other line says so too*). */
function labelsUnknownNote(d) {
  const error = d.labelError || 'the protection service did not answer';
  const cause = UNREACHABLE_REFUSAL.test(error) ? 'down' : error === LABELS_NOT_CONNECTED ? 'not-connected' : d.labelError ? 'said' : null;
  if (offCause(cause) === 'not-running') return [...cannotCheck('', 'not-running', false, 'the levels of your files show here'), ' You can still choose rules.'];
  if (cause === 'down') return [...cannotCheck('Labels could not be read.', 'down', true), ' You can still choose rules.'];
  return 'Labels could not be read: ' + error + '. You can still choose rules.';
}
/** The note's words follow the poll: one drawn over unknown labels keeps
 *  what it was drawn with (F.noteOff), and a poll that turns not running on
 *  or off, or names other commands, draws it again, the list as it is. */
function followFilesNote() {
  const d = F.data;
  if (!(d && d.labels === 'unknown') || F.noteOff === JSON.stringify(offKey())) return;
  F.noteOff = JSON.stringify(offKey());
  filesNote(labelsUnknownNote(d));
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
  // The line names only the button in sight (suggestedLine); before the
  // first read it keeps the markup's words, which claim neither keys nor none.
  if (G.loaded) drawSuggestedLine();
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
    const from = labelFrom(l, entry.path);
    const see = madeFromLink(l, entry.path);
    if (from) out.push(el('div', { class: 'dim file-from', title: l.via || '' }, from, see ? ' ' : null, see));
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
/** What runs changed (followRunningAnswers): every answer said whether
 *  protection was on then. Each open "What the rules say" asks again and
 *  keeps its answer until the new one replaces only the box (hosts being
 *  typed in its row stay); a closed row's answer is forgotten, so it asks
 *  when opened. Find a rule's answer for a typed path asks again too. */
function readWhyRunning() {
  const open = new Set([...document.querySelectorAll('.file-why[data-path]')].map((box) => box.getAttribute('data-path')));
  for (const p of [...F.why.keys()]) {
    if (open.has(p)) loadWhy(p);
    else F.why.delete(p);
  }
  if (FIND_WHY.text !== null && !FIND_WHY.timer) readFindWhy(FIND_WHY.text);
}
/** The newest read of each path's "What the rules say": an older one that
 *  answers last is not drawn (readWhyRunning asks while one may be out). */
const WHY_ASKED = new Map();
let whySeq = 0;
async function loadWhy(path) {
  const mine = ++whySeq;
  WHY_ASKED.set(path, mine);
  const r = await apiGetControl('files/why?path=' + encodeURIComponent(path)).catch(() => null);
  if (!F.why.has(path) || WHY_ASKED.get(path) !== mine) return;
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
/** Why the second menu is off on a row with no rule: the first one starts it. */
const SEND_FIRST = 'Choose who may read it first. Then you can choose where it may be sent.';

/** A file row names your answers about that file (dashboard.md §4.25n, *A
 *  file's row names your answers about it*): the standing answers about
 *  sending it, which Sending data lists one row each. Kept: a send (`network`)
 *  answered Always allow or Block whose `origin` is a file path, exactly.
 *  Left out: an answer that no longer applies, an environment variable
 *  (`env:`), and the answers of a program or of a session (`holder-send:`,
 *  `session-net:`), which cover a set of files or a whole session, not
 *  this file. */
function keepFileAnswer(v) {
  if (v.status !== 'approved' && v.status !== 'denied') return;
  if (!fileSend(v)) return;
  const list = F.answers.get(v.origin) || [];
  list.push({ id: v.id, host: v.target, approved: v.status === 'approved' });
  F.answers.set(v.origin, list);
}
/** A send (`network`) of one file, by the absolute path in its `origin`:
 *  not an answer that no longer applies, an environment variable (`env:`),
 *  nor a program's or a session's question (`holder-send:`, `session-net:`,
 *  `session-exec:`), which covers a set of files or a whole session. */
function fileSend(v) {
  if (v.where !== 'network' || v.noLongerApplies) return false;
  if (typeof v.origin !== 'string' || !v.origin.startsWith('/')) return false;
  return !/^(?:holder-send|session-net|session-exec):/.test(v.subject || '');
}
/** A file row names the sends of that file that wait for your answer
 *  (dashboard.md §4.25n, *and the sends of it that wait*): a waiting
 *  question (`pending`) about sending exactly that file, by the rules of
 *  keepFileAnswer. A host asked twice is named once, by its newest question
 *  (the panel lists the newest first). */
function keepFileWaiting(v) {
  if (v.status !== 'pending' || !fileSend(v)) return;
  const list = F.waiting.get(v.origin) || [];
  if (list.some((w) => w.host === v.target)) return;
  list.push({ id: v.id, host: v.target });
  F.waiting.set(v.origin, list);
}
/** The line under a file row's second menu: each host a link to its answer
 *  row under Sending data (openAnswerRule), then the words and mark that
 *  row has. At most FILE_ANSWERS_SHOWN, then how many more. Compared by the
 *  absolute path, never the `~/` one; a folder or a pattern has none (its
 *  files' own rows have theirs). Null with none. */
const FILE_ANSWERS_SHOWN = 3;
let fileAnswersSeq = 0;
function fileAnswersLine(t) {
  const answers = t.kind === 'file' ? F.answers.get(t.path) : null;
  if (!answers || !answers.length) return null;
  const line = el('p', { class: 'dim file-answers', id: 'file-answers-' + (++fileAnswersSeq) }, 'Your answers: ');
  for (const [i, a] of answers.slice(0, FILE_ANSWERS_SHOWN).entries()) {
    if (i) line.append(' · ');
    // One answer is one box: the line wraps between answers, never between
    // a host and its effect.
    line.append(el('span', { class: 'file-answer' }, answerRuleLink(a.id, { class: 'file-answer-link' }, nameCode(a.host)), ' ',
      el('span', { class: 'outcome ' + (a.approved ? 'ok' : 'bad') }, svg(a.approved ? ICON.check : ICON.x, 14), a.approved ? 'Always allowed' : 'Always blocked')));
  }
  const more = answers.length - FILE_ANSWERS_SHOWN;
  if (more > 0) line.append(' · and ' + more + ' more');
  return line;
}
/** The line under fileAnswersLine: each waiting send's host a link to its
 *  question in Approvals, which opens marked (`/approvals/<id>`, §4.25b; a
 *  modifier click is the browser's). At most FILE_ANSWERS_SHOWN, then how
 *  many more, a link to Approvals itself. Nothing is answered here: the card
 *  in Approvals says what each answer does. Null with none. */
let fileWaitingSeq = 0;
function fileWaitingLine(t) {
  const waiting = t.kind === 'file' ? F.waiting.get(t.path) : null;
  if (!waiting || !waiting.length) return null;
  const line = el('p', { class: 'dim file-waiting', id: 'file-waiting-' + (++fileWaitingSeq) }, 'Waiting for your answer: ');
  for (const [i, w] of waiting.slice(0, FILE_ANSWERS_SHOWN).entries()) {
    if (i) line.append(' · ');
    line.append(el('span', { class: 'file-answer' }, el('a', { href: routeHref('approvals', w.id), 'data-page-link': 'approvals', 'data-ask': w.id, class: 'file-waiting-link' }, nameCode(w.host))));
  }
  const more = waiting.length - FILE_ANSWERS_SHOWN;
  if (more > 0) line.append(' · ', el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', class: 'file-waiting-link', text: 'and ' + more + ' more' }));
  return line;
}
/** The lines under the menu `sel`, which a screen reader then hears with it. */
function withFileAnswers(cell, sel, t) {
  for (const line of [fileAnswersLine(t), fileWaitingLine(t)]) {
    if (!line) continue;
    const was = sel.getAttribute('aria-describedby');
    sel.setAttribute('aria-describedby', (was ? was + ' ' : '') + line.id);
    cell.append(line);
  }
}

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
  } else if (level === null && !isLocked(t)) {
    // Greyed with no rule at all: say where a rule starts (§4.25p, *The
    // browser names its menus*).
    sel.setAttribute('aria-label', 'Where ' + t.display + ' may be sent. ' + SEND_FIRST);
    sel.title = SEND_FIRST;
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
  // Not secret, or no label at all: nothing is withheld, so no answer is
  // named under it.
  if (mode === 'ask' || mode === 'hosts') withFileAnswers(cell, sel, t);
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
let perValueHowSeq = 0;
function perValuePick(cell, t, st, own) {
  // The menu cannot change the hosts, so the line under the sentence says,
  // on the page, where they are changed: a disabled control is skipped by
  // Tab and a touch screen shows no title (dashboard.md §4.25p, *Per value*).
  const how = el('p', { class: 'dim file-values-how', id: 'per-value-how-' + (++perValueHowSeq) },
    'Each value has its own hosts, so this menu cannot change them. Edit ', nameCode('values:'),
    own === null ? ' in the rule it inherits, in ' : ' for this file in ', nameCode(policyFileName()), '.');
  const words = own === null ? inheritedSend(t, 'Per value', 'Each value has its own hosts. Change them in ' + policyFileName() + '.') : null;
  const sel = el('select', { class: 'label-select send-select', 'aria-label': words || 'Where ' + t.display + ' may be sent', title: words || how.textContent, 'aria-describedby': how.id });
  sel.append(el('option', { value: 'values', text: 'Per value' }));
  sel.value = 'values';
  sel.disabled = true;
  cell.append(el('span', { class: 'label-pick send-pick' + (st.waiting !== undefined ? ' waiting' : ''), 'data-send': 'values', 'data-from': own === null ? 'values' : null },
    el('span', { class: 'label-dot', 'aria-hidden': 'true' }), sel));
  // Each key and host a name kept whole (§4.25u, *Rules names each host*).
  cell.append(el('p', { class: 'dim file-values' }, askCellWords(t.label.sendParts, t.label.send)));
  cell.append(how);
  withFileAnswers(cell, sel, t);
  return cell;
}
/** The policy file as the page names it: the path the panel reports, home
 *  as `~` (as the rule-source panel heads its lines), else its bare name. */
function policyFileName() {
  const f = S.panel && S.panel.policyFile;
  return f && f.path ? shortPath(f.path) : 'policy.yaml';
}

/** The tooltip and name of a second menu that follows a label from
 *  elsewhere: its choice and where it comes from, as the row's line says it
 *  ("Where ~/proj/notes/a.md may be sent: listed hosts without asking. From
 *  your rule on ~/proj/notes. Change it there."). */
function inheritedSend(t, choice, more) {
  const from = labelFrom(t.label, t.path).replace(/\.$/, '');
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
  if (d && d.labels === 'unknown') { F.noteOff = JSON.stringify(offKey()); filesNote(labelsUnknownNote(d)); }
  else if (d && d.axis === false) filesNote('Protection is off. These rules take effect when you turn it on in Settings.');
  else filesNote('');
  // The folder's own label.
  const self = document.getElementById('files-self');
  clear(self);
  self.hidden = !(d && d.self);
  if (d && d.self) {
    self.append(el('span', { class: 'dim', text: 'This folder: ' }), labelChip(d.self));
    const from = labelFrom(d.self, d.path);
    if (from) self.append(' ', el('span', { class: 'dim', text: from }));
    const see = madeFromLink(d.self, d.path);
    if (see) self.append(' ', see);
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
  // The heads stand over rows only, not over an empty folder or no listing.
  document.getElementById('files-list-heads').hidden = !list.querySelector('.row.file:not(.up)');
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
/** Under a rule whose path has nothing on this computer (`missing`, the
 *  server's look at the disk; dashboard.md §4.25f *A rule on nothing says
 *  so*). Its shape stays ruleShape's, so an edit keeps the rule's reach;
 *  only its icon is a file's, as a missing path is not known to be a folder. */
const RULE_MISSING_WORDS = 'Nothing at this path on this computer. The rule applies if something appears here; if you meant another file, check the spelling.';
function ruleMissing(r) { return r.missing === true && !isPatternRule(r); }

function renderLabeled() {
  const host = document.getElementById('files-tree');
  if (!host) return;
  clear(host);
  if (!S.panel) {
    // Said once for all of Your rules (the list below stays hidden), with the
    // cause the page knows (panelCause; followCannotCheck draws it again).
    // The file browser works without the service and marks its labels
    // unknown, but not without the dashboard: no answer offers no add.
    showFilesGroup(true, false);
    renderFilesMissing(false);
    renderFilesOpensNote([]);
    const cause = panelCause(S.panelFailure);
    F.unreadCause = causeKey(cause);
    const line = el('div', { class: 'empty-row dim' }, ...cannotCheck('Your rules could not be read.', cause, true, 'your rules show here'));
    if (cause !== 'gone') line.append(' You can still ', el('button', { type: 'button', class: 'link-btn', text: 'add a rule', onclick: () => setFilesView('all') }), '.');
    host.append(line);
    return;
  }
  F.unreadCause = false;
  // Find a rule (§4.25f): only the rules that hold the text, and the folders
  // on the way to them; with none, the group is not drawn, its title with it.
  const q = findText();
  const found = F.rules.filter((r) => ruleMatches(r, q));
  showFilesGroup(!q || found.length > 0, F.rules.length > 0);
  renderFilesMissing(!q || found.length > 0);
  renderFilesOpensNote(found);
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
/** Under the Files and folders heading (dashboard.md §4.25f *A rule on
 *  nothing says so*): how many of your file rules name a path where nothing
 *  is, and up to RULES_MISSING_SHOWN of their paths as buttons that open the
 *  row (openRuleRow unfolds, empties Find a rule and focuses its ⋯). It
 *  counts every rule, not only those Find a rule found, so it does not come
 *  and go with the box; `shown` false (the group hidden, the panel unread)
 *  draws nothing. Not drawn with none. */
const RULES_MISSING_SHOWN = 3;
function renderFilesMissing(shown) {
  const line = document.getElementById('files-missing');
  if (!line) return;
  clear(line);
  const lost = shown ? F.rules.filter(ruleMissing) : [];
  line.hidden = !lost.length;
  if (!lost.length) return;
  // One button a path: two sources on one path open the same row.
  const paths = [...new Set(lost.map((r) => r.path))];
  line.append(n(lost.length, 'rule names', 'rules name') + ' a path where nothing is on this computer: ');
  for (const [i, p] of paths.slice(0, RULES_MISSING_SHOWN).entries()) {
    if (i) line.append(', ');
    line.append(el('button', { type: 'button', class: 'link-btn', title: p, onclick: () => openRuleRow(p) }, el('code', { text: shortPath(p) })));
  }
  const more = paths.length - RULES_MISSING_SHOWN;
  line.append(more > 0 ? ', and ' + more + ' more, each marked below.' : '.');
}
/** A file rule's row draws its Opens it line (dashboard.md §4.25p) only
 *  where it differs from the default: a secret rule that names programs
 *  (`readers:`). A rule with none (`opensDefault`) draws no line; an older
 *  server that sends no flag keeps the line. */
function opensShown(r) { return !!r.opens && r.level !== 'public' && !r.opensDefault; }
/** Under the Files and folders heading (§4.25p *Opens it*): the default
 *  that the rows without an Opens it line share, said once, while at least
 *  one such secret row is listed (`rows`, what Find a rule keeps). A
 *  program the file's consumer table names (ssh for a key) may still get
 *  the real file with no `readers:`, so the note says so; the opened row
 *  names it. */
const FILES_OPENS_WORDS = 'A program that opens one of these files gets a masked copy, unless the file\'s rule names the program or Mandu knows the program needs that file, as ssh needs your SSH keys. Open a file to see which programs get the real one.';
function renderFilesOpensNote(rows) {
  const note = document.getElementById('files-opens-note');
  if (!note) return;
  const show = rows.some((r) => r.level && r.level !== 'public' && !opensShown(r));
  note.hidden = !show;
  note.textContent = show ? FILES_OPENS_WORDS : '';
}
/** The Files and folders group, its title and column heads with it: not
 *  drawn while Find a rule finds none of its rules. The heads are drawn only
 *  over a rule row (`rows`): not over the line that says there is none, or
 *  that Your rules could not be read. */
function showFilesGroup(shown, rows) {
  for (const id of ['files-group', 'files-heads', 'files-tree']) {
    const x = document.getElementById(id);
    if (x) x.hidden = !shown || (id === 'files-heads' && !rows);
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
  // The mark opens the row, where its words are said in full with the
  // place they name as a link (dashboard.md §4.25p): never a hover only.
  if (r.warning) {
    name.append(' ', el('button', { type: 'button', class: 'file-warn-mark', 'aria-label': r.warning, title: r.warning,
      onclick: () => (F.rule === key ? afterToggle('#files-tree', r.path) : toggle(false)) }, svg(ICON.alert, 14)));
  }
  const text = el('div', { class: 'file-text' }, name);
  if (ruleMissing(r)) text.append(el('div', { class: 'dim file-missing', text: RULE_MISSING_WORDS }));
  if (opensShown(r)) text.append(el('div', { class: 'dim file-opens' }, el('span', { class: 'file-opens-k', text: 'Opens it' }), ' ', r.opens));
  const p = pendingFor(t);
  if (p) text.append(el('div', { class: 'file-pending' }, ...willBe(p)));
  const toggle = (hosts) => {
    F.rule = F.rule === key && !hosts ? null : key;
    renderLabeled();
    afterToggle('#files-tree', r.path, hosts);
  };
  row.append(
    el('div', { class: 'file-cell' }, el('span', { class: 'row-icon' }, svg(t.kind === 'pattern' ? ICON.pattern : t.kind === 'dir' && !ruleMissing(r) ? ICON.folder : ICON.file, 18)), text),
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
    const from = labelFrom(t.label, t.path);
    if (from) now.append(el('span', { class: 'dim', text: from }));
    const see = madeFromLink(t.label, t.path);
    if (see) now.append(see);
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
  // A rule on nothing says so, in place of words about a file or folder.
  if (t.rule && ruleMissing(t.rule)) notes.push(RULE_MISSING_WORDS);
  else if (t.kind === 'dir' || t.kind === 'missing') notes.push('A folder\'s rule covers everything inside it, except files with a rule of their own.');
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
    if (r.warning) out.push(el('p', { class: 'rule-warn', role: 'note' }, warningWords(r)));
    if (r.sourceNote) out.push(el('p', { class: 'dim detail-note', text: r.sourceNote }));
    if (r.origin) out.push(originLine(r.origin, e.display, r.path ? shortPath(r.path) : null));
    if (r.used) out.push(el('p', { class: 'dim detail-note' }, ...useLine(r)));
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
      // Its sessions on History (§4.25f *A rule finds its sessions*): the
      // path as the row names it, the words History finds a secret card by.
      // Not for a pattern: the search matches words, not globs.
      links.append(historySearchLink(e.display, 'Its sessions on History', 'rule-sessions-link'));
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
  // Another tab's change waits to be read once this tab's Save answers
  // (afterSave): it is not written over meanwhile.
  if (!(F.saving && F.syncLater)) {
    if (F.pending.size) lsSet(FILES_PENDING_KEY, JSON.stringify([...F.pending.values()]));
    else lsDel(FILES_PENDING_KEY);
  }
  renderRulesMark();
}
/** The changes this browser keeps waiting, as stored; a damaged entry reads
 *  as none. */
function storedPending() {
  try {
    const list = JSON.parse(lsGet(FILES_PENDING_KEY) || '[]');
    return Array.isArray(list) ? list.filter((p) => p && typeof p.path === 'string') : [];
  } catch { return []; }
}
function restorePending() {
  for (const p of storedPending()) F.pending.set(p.path, p);
  renderRulesMark();
}

/** Changes to save are the same in every tab (dashboard.md §4.25n *Changes
 *  to save are the same in every tab*). Each tab keeps the list in this
 *  browser's storage; another tab's choice, Drop, Discard or Save rewrites
 *  it, and the `storage` event this tab gets then takes the list as stored:
 *  until 2026-10-26 each tab read it once at load and wrote its own over it,
 *  so a choice made in one tab was lost when another wrote, and a Save or a
 *  Discard in one left the other offering the same changes again. A choice
 *  keeps the rule version it was made against (no pendingVersionsNow, no
 *  read of the server): a rule changed meanwhile still refuses its Save.
 *  Nothing is written back. While this tab's Save is on its way the event
 *  waits for its answer (afterSave). `key` null: the storage was cleared. */
function syncFromOtherTab(e) {
  const pending = e.key === FILES_PENDING_KEY || e.key === null;
  const skipped = e.key === SUGG_SKIP_KEY || e.key === null;
  if (!pending && !skipped) return;
  if (F.saving) { F.syncLater = true; return; }
  if (pending) {
    const stored = storedPending();
    if (JSON.stringify(stored) !== JSON.stringify([...F.pending.values()])) F.expected = null;
    F.pending.clear();
    for (const p of stored) F.pending.set(p.path, p);
  }
  if (skipped) {
    G.skip.clear();
    for (const id of storedSkipped()) G.skip.add(id);
  }
  syncDraw(skipped);
}
/** What pendingChanged draws, without keeping the list: the top bar's mark
 *  on every page; the rest on Rules only, the focus kept as a poll keeps it,
 *  else when the person comes back to Rules (renderExplorer). */
function syncDraw(skipped) {
  renderRulesMark();
  if (S.page !== 'rules' || !F.started) { F.syncStale = true; return; }
  F.syncStale = false;
  const block = document.getElementById('rules-block');
  const place = block ? pollPlace(block) : null;
  const had = barPlace();
  if (skipped) renderSuggested();
  renderPending();
  if (F.data || F.typed) renderFiles({ placed: !!place });
  renderLabeled();
  pollRefocus(place);
  barRefocus(had);
  refreshImpact();
}
/** This tab's Save answered: a change another tab made meanwhile is read
 *  now. Each stored change exactly as this Save sent it (`sent`, path →
 *  JSON) is as the Save left it here: saved, gone; refused, as this tab
 *  has it. Every other stored change stays as the other tab left it, and
 *  a choice this tab made meanwhile is kept. */
function afterSave(sent) {
  F.saving = false;
  if (!F.syncLater) return;
  F.syncLater = false;
  const next = new Map();
  for (const p of storedPending()) {
    const mine = sent.get(p.path) === JSON.stringify(p) ? F.pending.get(p.path) : p;
    if (mine) next.set(p.path, mine);
  }
  for (const p of F.pending.values()) if (!next.has(p.path) && !sent.has(p.path)) next.set(p.path, p);
  // A question asked about the list holds while the list is the same.
  if (JSON.stringify([...next.values()]) !== JSON.stringify([...F.pending.values()])) F.expected = null;
  F.pending.clear();
  for (const p of next.values()) F.pending.set(p.path, p);
  savePending();
  G.skip.clear();
  for (const id of storedSkipped()) G.skip.add(id);
  syncDraw(true);
}

/** The top bar's Rules link says how many levels chosen on Rules wait to be
 *  saved, on every page (dashboard.md §4.25n *The top bar says when Rules
 *  has changes not saved*): until 2026-10-25 a person who chose No AI for a
 *  file and went Home saw nothing saying the AI still read it as before. It
 *  counts the person's own choices (F.pending), never Mandu's ticked
 *  suggestions, and is drawn wherever the list changes or is kept
 *  (savePending), once at start (restorePending), and when another tab
 *  changes the list (syncDraw).
 *
 *  While Mandu refuses your last edit to policy.yaml the same slot shows
 *  "!" in a warn ring instead (§4.25 *An edit to policy.yaml Mandu
 *  refused*, *The top bar says so on every page*): a Save from Rules writes
 *  that file, so the refusal is what to fix first, and the name says both.
 *  The poll passes each answer (`home`), the one condition Home's notice
 *  follows (refusedPolicyPath); the other callers pass none and keep the
 *  last answer's word, and a failed poll does not call it, so the mark
 *  stays as drawn: a failed poll says nothing about the file. The only
 *  writer of the link's name and title. Drawn once across calls. */
let rulesFileRefused = false;
function renderRulesMark(home) {
  if (home !== undefined) rulesFileRefused = refusedPolicyPath(home) !== null;
  const mark = document.getElementById('nav-rules-unsaved');
  if (!mark) return;
  const link = mark.parentElement;
  const count = F.pending.size;
  const refused = rulesFileRefused;
  if (sameAsDrawn('rules-mark', [count, refused])) return;
  mark.textContent = refused ? '!' : String(count);
  mark.classList.toggle('refused', refused);
  mark.hidden = !refused && count === 0;
  const words = [
    ...(refused ? ['Mandu did not take your last edit to policy.yaml'] : []),
    ...(count ? [n(count, 'change', 'changes') + ' not saved'] : []),
  ];
  if (words.length) {
    const name = 'Rules, ' + words.join(', ');
    link.setAttribute('aria-label', name);
    link.title = name;
  } else {
    link.removeAttribute('aria-label');
    link.removeAttribute('title');
  }
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
        const at = [...F.pending.keys()].indexOf(p.path);
        F.pending.delete(p.path);
        pendingChanged();
        dropNotice(p, at);
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

/** "3 changes discarded." with Undo, after Discard. Undo posts nothing: it
 *  puts the changes back in Changes to save, to wait for Save again. */
function discardNotice(kept) {
  const count = kept.pending.length + kept.skipped.length;
  if (!count) return;
  rulesNotice(n(count, 'change', 'changes') + ' discarded.', null);
  DISCARDED = kept;
  const box = document.getElementById('rules-notice');
  box.append(noticeUndo(box, 'Your rules', () => undoDiscard(box), 'Undo the discard'));
}
/** "Your change to ~/ws/.env dropped." with Undo, after Drop on one row
 *  (dashboard.md §4.25n *Drop can be undone*): the store of Discard with
 *  that one entry, no key, and `at`, its place in the list. */
function dropNotice(p, at) {
  rulesNotice(['Your change to ', ...fitName(p.display), ' dropped.'], null);
  DISCARDED = { pending: [p], skipped: [], at };
  const box = document.getElementById('rules-notice');
  const undo = noticeUndo(box, 'Your rules', () => undoDiscard(box));
  undo.setAttribute('aria-label', 'Undo the drop in Your rules');
  box.append(undo);
}
function undoDiscard(box) {
  const kept = DISCARDED;
  if (!kept) return;
  const had = box.contains(document.activeElement);
  DISCARDED = null;
  if (typeof kept.at === 'number') { undoDrop(kept.pending[0], kept.at, had); return; }
  for (const p of kept.pending) if (!F.pending.has(p.path)) F.pending.set(p.path, p);
  // A key the last read no longer lists (the scan ran again) cannot come back.
  const live = new Set(G.rows.filter((s) => s.applicable).map((s) => s.id));
  const back = kept.skipped.filter((id) => live.has(id));
  for (const id of back) G.skip.delete(id);
  saveSkipped();
  renderSuggested();
  // Drawn while Undo is still there, so the focus it has is not moved; the
  // notice's new words then draw Undo away, and the focus goes to the bar.
  pendingChanged();
  const all = kept.pending.length + kept.skipped.length;
  const gone = kept.skipped.length - back.length;
  const count = all - gone;
  rulesNotice(!gone ? 'Your changes are back. Nothing is saved until you press Save.'
    : !count ? 'None of your changes could come back: ' + n(gone, 'key is', 'keys are') + ' no longer found.'
    : count + ' of ' + n(all, 'change', 'changes') + (count === 1 ? ' is' : ' are') + ' back; ' + n(gone, 'key is', 'keys are') + ' no longer found. Nothing is saved until you press Save.', null);
  barRefocus(had);
}
/** The Undo of a Drop: the entry back at its place in the list, as it was,
 *  unless a newer choice for its path waits (another tab made one): that
 *  one is kept, and the line says so. */
function undoDrop(p, at, had) {
  const newer = F.pending.has(p.path);
  if (!newer) {
    const list = [...F.pending.values()];
    list.splice(Math.max(0, Math.min(at, list.length)), 0, p);
    F.pending.clear();
    for (const q of list) F.pending.set(q.path, q);
    pendingChanged();
  }
  rulesNotice(newer ? ['Your change to ', ...fitName(p.display), ' is not back: a newer change to it waits.']
    : 'Your change is back. Nothing is saved until you press Save.', null);
  barRefocus(had);
}
/** A new change in the bar: the discarded set would mix with it, so the
 *  notice keeps its words and loses its Undo. */
function dropDiscardUndo() {
  if (!DISCARDED) return;
  DISCARDED = null;
  for (const b of document.querySelectorAll('#rules-notice button')) b.remove();
}

/** Queue one change per target (a rule keeps its own reach). Ticked rows
 *  stay ticked, and each row's dots show the choice waiting. */
function queueChanges(level, bindings, targets) {
  dropDiscardUndo();
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
 *  `{count, newest}`, how many were saved and the id of the newest change
 *  (the route applies them in order), or null when nothing more should be sent.
 *  Several saved, the notice links the newest in Approvals, where the
 *  others sit beside it under Rule changes (dashboard.md §4.25m). */
async function saveSuggestions(err) {
  const ids = suggestedPending().map((s) => s.id);
  if (!ids.length) return { count: 0, newest: null };
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
  const newest = applied.map((a) => a.changeId).filter((id) => typeof id === 'string' && RULE_CHANGE_ID.test(id)).pop() || null;
  if (applied.length) {
    RULES_READS.wrote();
    const said = n(applied.length, 'suggestion', 'suggestions') + ' saved.';
    rulesNotice(applied.length === 1 ? said : inRuleChanges(said + ' Each is its own change ', newest),
      applied.length === 1 ? applied[0].changeId : null);
  }
  renderSuggestionViews();
  return { count: applied.length, newest };
}

/** `head` + "in Approvals, under Rule changes.", those words a link to the
 *  change `changeId` there when it has one (changesLink). */
function inRuleChanges(head, changeId) {
  const link = changesLink(changeId, 'in Approvals, under Rule changes');
  return link ? [head, link, '.'] : head + 'in Approvals, under Rule changes.';
}

/** Save, with the changes another tab makes meanwhile kept for its answer
 *  (afterSave). `sent`: each change this Save sent, path → JSON. */
async function saveFileChanges() {
  const sent = new Map();
  F.saving = true;
  try { await saveFileChangesNow(sent); } finally { afterSave(sent); }
}
async function saveFileChangesNow(sent) {
  const err = document.getElementById('lock-error');
  const save = document.getElementById('files-save');
  const had = barPlace();
  err.textContent = '';
  const saved = await saveSuggestions(err);
  if (saved === null) { barRefocus(had, save); return; }
  if (!F.pending.size) {
    if (saved.count) await loadRules();
    barRefocus(had, save);
    return;
  }
  const body = { changes: pendingChanges(), folder: F.path || '~' };
  for (const p of F.pending.values()) sent.set(p.path, JSON.stringify(p));
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
  // Only what was sent is saved: a choice made meanwhile, here or in
  // another tab, still waits.
  const count = sent.size;
  for (const [path, json] of sent) if (F.pending.has(path) && JSON.stringify(F.pending.get(path)) === json) F.pending.delete(path);
  F.expected = null;
  F.why.clear();
  forgetFindWhy();
  savePending();
  document.getElementById('files-reason').value = '';
  // With suggestions saved too, Undo names the file changes it takes back
  // ("Undo the 4 changes"), and the suggestions, each its own change, are
  // linked in Approvals.
  const head = n(count, 'change', 'changes') + ' saved';
  rulesNotice(saved.count ? inRuleChanges(head + ', and ' + n(saved.count, 'suggestion', 'suggestions') + (saved.count === 1 ? ', its own change ' : ', each its own change '), saved.newest) : head + '.',
    r.data.changeId || null, saved.count ? 'Undo the ' + n(count, 'change', 'changes') : undefined);
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
 *  moves them there, unchanged, so they get History and Undo like the rest.
 *  It asks first, in the notice, in place of the button (askBox): Move them
 *  posts, Cancel gives the focus back to the button. */
function renderMoveNotice() {
  const box = document.getElementById('files-move');
  const held = askHeld();
  clear(box);
  const labels = (S.secrets && S.secrets.panel && S.secrets.panel.labels) || [];
  const count = labels.filter((l) => l.source && l.source !== 'policy-file').length;
  box.hidden = count === 0;
  if (!count) {
    if (asking('move')) ASKING = null;
    return;
  }
  box.append(el('span', { text: n(count, 'rule was', 'rules were') + ' made on this page before rules were kept in policy.yaml. Changes to them are not listed under Rule changes and cannot be undone. ' }));
  const ask = askBox('move', 'Move ' + n(count, 'rule', 'rules') + ' into policy.yaml? Protection does not change. The move itself cannot be undone.', 'Move them', moveRules, () => {
    renderMoveNotice();
    const b = box.querySelector('.files-move-btn');
    if (b) b.focus();
  });
  if (ask) box.append(ask);
  else {
    box.append(el('button', { type: 'button', class: 'btn small files-move-btn', text: 'Move them into policy.yaml', onclick: (e) => {
      // Where the focus is, taken at the press: after the move, the
      // heading once the notice is gone; the button, described, after a
      // refusal, whose words are shown here (Changes to save, hidden while
      // nothing waits, said nothing until 2026-10-11).
      const place = settingsPlace(e.target);
      askInPlace('move', { place });
      renderMoveNotice();
      focusAsk(box, place);
    } }));
  }
  askRefocus(held);
}
async function moveRules(ask, data) {
  const box = document.getElementById('files-move');
  data.busy = true;
  busyRow(ask, true);
  const r = await apiPost('files/move-page-rules');
  data.busy = false;
  if (asking('move') === data) ASKING = null;
  if (!r.ok) {
    renderMoveNotice();
    showAskError(box, refusalText(r, 'could not move the rules'));
    settingsRefocus(data.place, box);
    return;
  }
  RULES_READS.wrote();
  rulesNotice('Moved ' + n(r.data.moved, 'rule', 'rules') + ' into policy.yaml.', null);
  await loadRules();
  if (F.path) await openFolder(F.path);
  settingsRefocus(data.place);
}

/** The explorer after the rules are read: the tree, the list (its own-model
 *  column follows the declared models), and on the first read the view last
 *  used and any changes still waiting. */
function renderExplorer() {
  renderLabeled();
  renderMoveNotice();
  if (!F.started) {
    F.started = true;
    F.syncStale = false;
    const last = lsGet(FILES_VIEW_KEY);
    // A page from before the panels were separate remembered 'suggested'.
    setFilesView(last === 'all' ? 'all' : 'labeled');
    if (lsGet(SUGG_OPEN_KEY) === '1' || last === 'suggested') setSuggestedOpen(true);
    renderPending();
    if (F.pending.size) refreshImpact();
    return;
  }
  // Another tab changed the list while this one showed another page.
  if (F.syncStale) {
    F.syncStale = false;
    renderSuggested();
    renderPending();
    refreshImpact();
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
    // Discard skips the suggestions too; each can be ticked again, and
    // Undo ticks them again (discardNotice). suggestedPending() lists only
    // ids not skipped yet: those are the ones Discard itself skips.
    const kept = { pending: [...F.pending.values()], skipped: suggestedPending().map((sg) => sg.id) };
    for (const id of kept.skipped) G.skip.add(id);
    saveSkipped();
    renderSuggested();
    F.pending.clear();
    pendingChanged();
    discardNotice(kept);
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
  noService: false,    // and no service answered that read (noService): suggestionsError
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
// The card's line before the suggestions are read (index.html), or while
// they cannot be: it claims neither keys nor none.
const SUGGESTED_LINE = 'Mandu looks for keys in your projects that no rule covers yet.';
// A scan the protection service cut short by stopping: the scan's own lead
// (server/suggestion-routes.ts), then the failed dial or the closed
// connection in its client's words, which the page says in its own. The
// line is drawn from a read that answered, so the service runs again.
const SCAN_CUT = /^The scan did not finish: /;
const SCAN_STOPPED_WORDS = 'The scan did not finish because the protection service stopped. Press ' + SCAN_LABEL + ' to try again.';

/** The suggestions this browser keeps skipped, as stored; a damaged entry
 *  reads as none. */
function storedSkipped() {
  try {
    const list = JSON.parse(lsGet(SUGG_SKIP_KEY) || '[]');
    return Array.isArray(list) ? list.filter((id) => typeof id === 'string') : [];
  } catch { return []; }
}
function restoreSkipped() {
  for (const id of storedSkipped()) G.skip.add(id);
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
      G.noService = noService(r);
      G.denied = !!(r && (r.status === 403 || r.status === 501));
    }
    G.loaded = true;
    // The poll reads every few seconds: redraw only what changed, so an
    // opened row stays as the person left it. A read no service answered
    // is drawn again when Mandu starts or stops (suggestionsError).
    const sig = JSON.stringify([G.rows, G.scan, G.error, G.error && G.noService ? offKey() : null]);
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
  drawSuggestedLine();
  renderSuggestionCard();
  renderSuggested();
  renderPending();
}

/** The line under the card's heading, closed or open (dashboard.md §4.25r
 *  *The closed card says whether any wait*): where the waiting keys were
 *  found; with none waiting, that a scan runs, when this dashboard's last
 *  scan looked and what it found (the line beside Scan for keys, its parts
 *  drawn the same way), or how to look: closed, press Review, then Scan for
 *  keys; opened, only Scan for keys, the button in sight. Suggestions that
 *  could not be read say neither: the page does not know. */
function drawSuggestedLine() {
  const line = document.getElementById('suggested-line');
  if (!line) return;
  clear(line);
  line.append(suggestedLine());
}
/** Is the card open (its Review button reads Close)? */
function suggestedOpen() {
  const view = document.getElementById('files-suggested-view');
  return !!view && !view.hidden;
}
function suggestedLine() {
  const scan = G.scan;
  if (G.rows.length) return document.createTextNode('Possible keys in ' + suggestionWhere(G.rows) + ' that no rule covers yet.');
  if (G.error) return document.createTextNode(SUGGESTED_LINE);
  // Scan for keys' own POST waits on the scan: it runs meanwhile.
  if (G.posting || (scan && scan.running)) return document.createTextNode('Scanning now… This can take a minute.');
  const at = scan && !scan.error && scan.summary ? whenNode(scan.finishedAt) : null;
  if (!at) {
    const how = suggestedOpen() ? 'Press ' + SCAN_LABEL + ' to' : 'Press Review, then ' + SCAN_LABEL + ', to';
    return document.createTextNode('None waiting. ' + how + ' look through the projects your agents worked in.');
  }
  const frag = document.createDocumentFragment();
  frag.append('None waiting. Mandu last looked at ', at, ': ', textParts(scan.summaryParts, scan.summary));
  return frag;
}

/** Where the waiting suggestions were found, for the Approvals card: "this
 *  project's git history", "the files of 2 projects", "your home folder". */
function suggestionWhere(rows) {
  const hist = rows.some((s) => s.source !== 'workspace' && s.source !== 'sensitivity-label' && s.source !== 'model-names' && s.source !== 'past-sessions');
  const files = rows.some((s) => s.source === 'workspace' || s.source === 'sensitivity-label' || s.source === 'model-names' || s.source === 'past-sessions');
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
  followSectionLinks();
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
 *  meanwhile, or another page opened. A card still hidden then (an empty
 *  Rule changes) leaves the page at its top. */
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
  if (!card || card.hidden) return;
  if (card.scrollIntoView) card.scrollIntoView({ block: 'start' });
  focusMarked(focus(card), true);
}

/** Each row drawn: its links, each with the card it follows when that
 *  card hides while empty (SECTIONS), else none. */
const SECTION_ROWS = [];
/** The row of links under the titles of Approvals, Rules and Settings,
 *  one per card (dashboard.md §4.25 *Section links*). A click scrolls its card to the
 *  top, gives the card's heading the focus and puts the card's key in the
 *  address, replaced, so Back still leaves the page. A modifier click is
 *  the browser's: the page at that card, in a new tab or window. */
function drawSectionLinks() {
  SECTION_ROWS.length = 0;
  for (const nav of document.querySelectorAll('nav.section-links[data-sections]')) {
    const page = nav.dataset.sections;
    const list = el('ul');
    const items = [];
    for (const [key, id, words, hides] of SECTIONS[page] || []) {
      const li = el('li');
      items.push({ li, card: hides ? document.getElementById(id) : null });
      list.append(li);
      li.append(el('a', { href: routeHref(page) + '#' + key, 'data-section': key, text: words, onclick: (e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button > 0) return;
        e.preventDefault();
        goToSection(page, key, id);
      } }));
    }
    clear(nav);
    nav.append(list);
    SECTION_ROWS.push(items);
  }
  followSectionLinks();
}
/** Each link to a card that hides while empty (Approvals' Keys Mandu
 *  found, asked-for rule changes and Rule changes, Rules' Files made from
 *  your secrets) or while unused (Settings' Dashboard account, shown only
 *  to a signed-in browser) shows only while its
 *  card does, so the row never offers a link that goes nowhere. Called
 *  where those cards are drawn. The row is changed in place, never drawn
 *  again: a poll moves neither the focus nor the scroll. The last link
 *  shown is marked `end`, which has no "·" after it. */
function followSectionLinks() {
  for (const items of SECTION_ROWS) {
    let last = null;
    for (const { li, card } of items) {
      const hide = !!card && card.hidden;
      if (li.hidden !== hide) li.hidden = hide;
      li.classList.remove('end');
      if (!hide) last = li;
    }
    if (last) last.classList.add('end');
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

/** Settings, at its Models card, the focus on Add a model: where a sentence
 *  that names Settings › Models leads (dashboard.md §4.25 *The hero links
 *  where it points*). While Add a model is hidden (the list could not be
 *  read), the focus goes to the card heading. */
function openModels() {
  return openAtCard('settings', 'settings-models-block', null, (card) => {
    const add = document.getElementById('model-open');
    return add && reachable(add) ? add : card && card.querySelector('h2');
  });
}

/** Rules, with the rule that decides `path` opened under Your rules
 *  (openRuleRow): where Change it under Rules on an Approvals card leads.
 *  The rule on the path itself, else the nearest folder rule above it. A
 *  file no rule of yours decides opens Rules at Your rules, its heading
 *  focused. */
function openRuleAt(path) {
  return openAtCard('rules', 'rules-block', null, (card) => {
    const r = typeof path === 'string' ? decidingRule(shortPath(path)) : null;
    if (!r) return card && card.querySelector('h2');
    openRuleRow(r.path);
    return null;
  });
}
/** Your rule on `shown` (a path as shortPath writes it, so a rule written
 *  with ~ and an absolute path meet), even one whose name reads as a
 *  pattern; else the deepest folder rule of yours with it inside; else
 *  null. */
function decidingRule(shown) {
  let best = null;
  for (const r of F.rules) {
    const at = shortPath(r.path).replace(/\/+$/, '');
    if (at === shown) return r;
    if (ruleShape(r) === 'dir' && shown.startsWith(at + '/') && (!best || at.length > shortPath(best.path).length)) best = r;
  }
  return best;
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
// that, once. Unless the server offers them the page does not draw the
// picker at all. It shows only the server's words and counts: nothing a
// model wrote.

function modelStatus(text) { document.getElementById('suggest-model-status').textContent = text || ''; }

/** The picker from the server's offer: which choices can be made and why not. */
function renderModelPicker() {
  const m = G.model;
  const sel = document.getElementById('suggest-model-tier');
  const own = document.getElementById('suggest-model-own');
  const run = document.getElementById('suggest-model-run');
  const why = document.getElementById('suggest-model-why');
  // Not offered (or no picker in the answer), the row, its preview and its
  // line are not drawn: a menu that can only be Off is a dead control
  // (dashboard.md §4.25t). It comes back the day the server offers it.
  const offered = !!(m && m.offered);
  const status = document.getElementById('suggest-model-status');
  document.getElementById('suggest-model').hidden = !offered;
  status.hidden = !offered;
  if (!offered) {
    G.preview = null;
    document.getElementById('suggest-model-preview').hidden = true;
    status.textContent = '';
  }
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
  // Each reason with the place it names as a link (Settings › Models).
  clear(why);
  if (!offered) return;
  why.append(m.hint);
  if (sel.value === 'off') for (const x of off) why.append(' ', x.label + ': ', textParts(x.whyParts, x.why));
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
  setWords(document.getElementById('suggest-error'), s && !running && s.error ? scanErrorText(s.error) : suggestionsError());
}

/** Why the suggestions could not be read, under Scan for keys: while Mandu
 *  is not running at all, a read that no service answered (noService) is no
 *  fault, the keys show once it starts (dashboard.md §4.25 *Every other line
 *  says so too*); any other refusal as loadSuggestions worded it. */
function suggestionsError() {
  if (!G.error) return '';
  return G.noService && notRunningNow() ? notRunningWords('the keys it finds show here') : G.error;
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
  drawSuggestedLine();
  const body = {};
  if (root) body.root = root;
  if (home) body.includeHome = true;
  const r = await apiPost('suggestions/scan', body);
  G.posting = false;
  if (!r.ok || !r.data) {
    btn.textContent = SCAN_LABEL;
    scanStatus('');
    drawSuggestedLine();
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
  if (on) dropDiscardUndo();
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
  // Under the advice, where each company's keys are replaced (§4.25r *The
  // advice says where to replace the key*): its own page, in a new tab, and
  // with no referrer, since the Rules address can name a file (?file=).
  if (s.rotate) {
    for (const r of s.replaceAt || []) main.append(replaceLine(r, 'suggestion-replace'));
  }
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
  links.append(el('button', { type: 'button', class: 'link-btn rule-source-btn suggestion-dismiss', text: 'Not a secret', 'aria-label': 'Not a secret: ' + named, onclick: () => dismissSuggestion(s) }));
  main.append(links);
  const ask = dismissAsk(s, named);
  if (ask) main.append(ask);
  main.append(lines);
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

/** Not a secret asks first, in the opened row (dismissAsk), its sentence
 *  focused when the focus was in the list; the place of the focus is taken
 *  at this press. Mark as not a secret posts (dismissNow), its button off
 *  during the POST. Done, the row is gone: the card's heading (pollRefocus),
 *  as Remove in Your rules. Refused: the question goes, and Not a secret
 *  gets the focus again, described by the card's error line. */
function dismissSuggestion(s) {
  const list = document.getElementById('files-suggested-list');
  const place = pollPlace(list);
  askInPlace('dismiss:' + s.id, { place });
  renderSuggested();
  focusAsk(list, place);
}
/** The question of Not a secret, under its buttons in the opened row. */
function dismissAsk(s, named) {
  return askBox('dismiss:' + s.id, ['Mark ', el('code', { text: named }), ' as not a secret? Mandu will not suggest it again, and the AI can still read it.'], 'Mark as not a secret',
    (ask, data) => dismissNow(s, ask, data),
    () => {
      renderSuggested();
      const b = [...document.querySelectorAll('#files-suggested-list .suggestion-dismiss')].find((x) => x.getAttribute('aria-label') === 'Not a secret: ' + named);
      if (b) b.focus();
    }, true);
}
async function dismissNow(s, ask, data) {
  const named = suggestionName(s);
  data.busy = true;
  busyRow(ask, true);
  const r = await apiPost('suggestions/dismiss', { id: s.id });
  data.busy = false;
  if (asking('dismiss:' + s.id) === data) ASKING = null;
  if (!r.ok || !r.data) {
    // The question goes; the Not a secret pressed gets the focus back,
    // described by the error line of the card.
    const a = document.activeElement;
    if (a && a.closest && a.closest('.ask-in-place')) a.blur();
    renderSuggested();
    setWords(document.getElementById('suggest-error'), refusalText(r, 'could not mark it as not a secret (' + r.status + ')'));
    pollRefocus(data.place);
    const btn = document.activeElement;
    if (btn && btn.classList.contains('suggestion-dismiss')) btn.setAttribute('aria-describedby', 'suggest-error');
    return;
  }
  G.skip.delete(s.id);
  setWritten(r.data);
  renderSuggestionViews();
  pollRefocus(data.place);
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
    // The card's line above says how to look, or when Mandu last looked.
    if (!G.error) list.append(el('div', { class: 'empty-row dim', text: 'No keys waiting.' }));
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
// `discarded`: the suggestion Discard took, while its line offers Undo
// (describeDiscarded); page memory only, never stored.
// `whereAt` / `whereAsked`: when the channel line was last read, and which
// read is the newest (describeWhere); `whereNotReady`: the line says no
// helper can run (describeWhereShown).
const D = { ctrl: null, sentence: '', focus: false, discarded: null, whereAt: 0, whereAsked: 0, whereNotReady: false };

function wireDescribe() {
  const form = document.getElementById('describe-form');
  const box = document.getElementById('describe-text');
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    suggestRules(box.value.trim());
  });
  document.getElementById('describe-cancel').addEventListener('click', () => { if (D.ctrl) D.ctrl.abort(); });
  box.addEventListener('input', describeLength);
  box.addEventListener('paste', describePasted);
  // Ctrl+Enter (Cmd+Enter on a Mac) presses Suggest rules: the button's
  // own path, so a press while it is off (the helper works) does nothing.
  // Enter alone still makes a new line.
  box.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || !(e.ctrlKey || e.metaKey) || e.altKey || e.isComposing) return;
    e.preventDefault();
    document.getElementById('describe-submit').click();
  });
  box.addEventListener('focus', () => { if (Date.now() - D.whereAt > WHERE_FRESH_MS) describeWhere(); });
  describeLength();
}

// ── Which AI reads what you write, or that none can (dashboard.md,
//    *Describe says which AI reads your words*) ─────────────────────────────
// Read when Rules opens, again when the box gets the focus once the last
// read is over 30 s old, and again when a press's answer is drawn (a PATH
// walk on the server, never per poll). The server answers an enum only;
// the words are the page's. A 501 or no answer draws nothing. Suggest rules
// stays on either way: signing in to Claude Code can fix "none" before the
// press, so the line says the 503's words without its "again"
// (helperNotReady), and is hidden while the 503's own alert says them under
// the box. What goes with the words is `explain({audience: "assistant"})`:
// a change to it changes these lines.
const WHERE_FRESH_MS = 30_000;
const WHERE_RULES = ' A summary of your rules goes with it: the files, sites and models they name, never a secret\'s value.';
const WHERE_BASE = ['ANTHROPIC_BASE_URL'];
const DESCRIBE_WHERE = {
  api: "What you write here goes to Anthropic's API, so that an AI can suggest rules." + WHERE_RULES,
  'api-custom': ownWords('What you write here goes to the AI at the address in ', WHERE_BASE, ', so that it can suggest rules.' + WHERE_RULES),
  claude: "What you write here goes through Claude Code on this computer to the AI it uses (Anthropic's, unless Claude Code is set otherwise), so that it can suggest rules." + WHERE_RULES,
  'claude-custom': ownWords('What you write here goes through Claude Code on this computer to the AI at the address in ', WHERE_BASE, ', so that it can suggest rules.' + WHERE_RULES),
  codex: "What you write here goes through Codex on this computer to the AI it uses (OpenAI's, unless Codex is set otherwise), so that it can suggest rules." + WHERE_RULES,
};
async function describeWhere() {
  D.whereAt = Date.now();
  const asked = ++D.whereAsked;
  let a = null;
  try { a = await apiGet('policy/assistant/channel'); } catch { a = null; }
  if (asked !== D.whereAsked) return;
  const line = document.getElementById('describe-where');
  D.whereNotReady = !!a && a.ready === false && typeof a.reason === 'string';
  const text = a && a.ready === true && Object.prototype.hasOwnProperty.call(DESCRIBE_WHERE, a.via) ? DESCRIBE_WHERE[a.via]
    : D.whereNotReady ? helperNotReady(a.reason)
    : '';
  clear(line);
  if (text) line.append(words(text));
  describeWhereShown();
}
/** The line shows when it has words, but a not-ready line not while the
 *  503's alert under the box says the same reason: one sentence, said once.
 *  It comes back when a new press clears the alert. */
function describeWhereShown() {
  const line = document.getElementById('describe-where');
  const host = document.getElementById('describe-result');
  line.hidden = !line.firstChild || (D.whereNotReady && !host.hidden && !!host.querySelector('.helper-unavailable'));
}

// ── The box's limit, said (dashboard.md *Describe what you want*) ─────────
// The box keeps 2,000 characters (its maxlength, the server's SENTENCE_MAX),
// and a browser cuts a longer paste without a word. Past 1,800 a quiet
// count shows (not a live region); a paste cut at the limit gets a line,
// announced once, that stays until the text is edited back under it.
const DESCRIBE_MAX = 2000;
const DESCRIBE_COUNT_FROM = 1800;
function describeLength(e) {
  const n = document.getElementById('describe-text').value.length;
  const count = document.getElementById('describe-count');
  count.hidden = n <= DESCRIBE_COUNT_FROM;
  count.textContent = count.hidden ? '' : n.toLocaleString('en-US') + ' of ' + DESCRIBE_MAX.toLocaleString('en-US') + ' characters';
  // The cut paste's own input keeps the line: a cut that falls inside a
  // character made of two code units lands one short of the limit.
  if (n < DESCRIBE_MAX && !(e && e.inputType === 'insertFromPaste')) describeCut(false);
}
/** A paste that would pass the limit: the box keeps its first part. The
 *  length it would make counts a pasted CRLF as one character, as the box
 *  does. */
function describePasted(e) {
  const box = document.getElementById('describe-text');
  const pasted = e.clipboardData ? e.clipboardData.getData('text/plain') : '';
  const kept = box.value.length - Math.max(0, box.selectionEnd - box.selectionStart);
  if (kept + pasted.replace(/\r\n?/g, '\n').length > DESCRIBE_MAX) describeCut(true);
}
function describeCut(on) {
  const line = document.getElementById('describe-cut');
  const text = on ? "Only the first 2,000 characters fit. Mandu's helper reads only those: shorten it or describe the rules in your own words." : '';
  if (line.textContent !== text) line.textContent = text;
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
  // A newer request: the discarded answer to an older one never comes back.
  D.discarded = null;
  describeWaits();
  clear(host);
  host.hidden = true;
  describeWhereShown();
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
  // The press ran the same selection: the line follows what it found.
  describeWhereShown();
  describeWhere();
}

// ── The helper cannot run (dashboard.md, *Describe what you want*) ────────
// The server answers 503 `{unconfigured: true, reason}`; the page says why
// in its own words, with the command that fixes it as code, and the server's
// original text only under Details, only for a cause it cannot word
// (`other`). No link: Settings has nothing that fixes any of these. The
// words equal the server's HELPER_WORDS (policy-assistant.ts), held equal by
// a unit test.
// A one-word code (`claude`, a key's name) has no space to keep whole: it
// is a plain <code>, named here, not a command kept whole (§4.25u).
const HELPER_SIGN_IN = ['Sign in to Claude Code (', ['claude'], '), then press Suggest rules again.'];
const HELPER_KEY = ['ANTHROPIC_API_KEY'];
const HELPER_REFUSALS = {
  'no-channel': ownWords("Mandu's helper uses Claude Code or Codex on this computer, or an Anthropic API key, and found neither. ", ...HELPER_SIGN_IN),
  'not-installed': ownWords("Mandu's helper is not installed with this copy of Mandu. Run ", ['mandu doctor', 'run'], ' to check this copy.'),
  'api-key-missing': ownWords("Mandu's helper is set to use an Anthropic API key, and found none. Set ", HELPER_KEY, ' for Mandu, then press Suggest rules again.'),
  'cli-missing': ownWords("Mandu's helper is set to use Claude Code or Codex on this computer, and did not find it. ", ...HELPER_SIGN_IN),
  other: "Mandu's helper cannot run right now.",
};
// Before a press, the line above the box (describeWhere) says the same
// sentence without "again": nothing was pressed yet. Derived from the words
// above, so the two cannot drift apart.
const HELPER_AGAIN = ', then press Suggest rules again.';
function helperNotReady(reason) {
  const text = HELPER_REFUSALS[Object.prototype.hasOwnProperty.call(HELPER_REFUSALS, reason) ? reason : 'other'];
  const parts = OWN_WORDS.get(text);
  const last = parts ? parts[parts.length - 1] : null;
  if (typeof last !== 'string' || !last.endsWith(HELPER_AGAIN)) return text;
  return ownWords(...parts.slice(0, -1), last.slice(0, -HELPER_AGAIN.length) + ', then press Suggest rules.');
}
function renderHelperUnavailable(host, d) {
  const known = Object.prototype.hasOwnProperty.call(HELPER_REFUSALS, d.reason);
  host.append(el('div', { class: 'ask-error helper-unavailable', role: 'alert' }, words(HELPER_REFUSALS[known ? d.reason : 'other'])));
  const detail = typeof d.detail === 'string' && d.detail ? d.detail : !known && typeof d.error === 'string' ? d.error : '';
  if (detail) host.append(el('details', { class: 'more describe-detail' }, el('summary', { text: 'Details' }), el('div', { class: 'dim', text: detail })));
}

function renderDescribeError(r) {
  const host = document.getElementById('describe-result');
  clear(host);
  host.hidden = false;
  const d = r.data || {};
  if (r.status === 503 && d.unconfigured) { renderHelperUnavailable(host, d); return; }
  host.append(el('div', { class: 'ask-error', role: 'alert' }, words(refusalText(r, 'could not suggest rules (' + r.status + ')'))));
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
  // Row i is edit i (the server maps its edits to rows one to one); if the
  // two ever differ in length, no row gets a mode line rather than a wrong one.
  const edits = Array.isArray(s.edits) && s.edits.length === rows.length ? s.edits : null;
  rows.forEach((row, i) => {
    const li = el('li', { class: row.loosens ? 'loosens' : '' });
    for (const p of row.parts || []) li.append(partNode(p, nameCode, (text) => document.createTextNode(text)));
    if (row.loosens) li.append(el('span', { class: 'tag-loosens', text: 'loosens protection' }));
    // A wide row says so beside its words; the foot says what it opens.
    if (row.overBroad) li.append(el('span', { class: 'tag-loosens tag-wide', text: 'Wide: type ALLOW' }));
    // A host's send rule in the Secrets mode says it would decide nothing,
    // as Your rules says once it is saved (sendRuleIdle).
    if (edits && editIdle(edits[i])) li.append(el('div', { class: 'dim rule-mode-note', text: SEND_RULE_IDLE_WORDS }));
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
  const discard = el('button', { type: 'button', class: 'btn', text: 'Discard', onclick: () => describeDiscarded(s) });
  const foot = el('div', { style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap' });
  let hint = null;
  if (rows.some((row) => row.overBroad)) {
    const box = confirmBox(apply, 'Type ALLOW to confirm this wide change', '', null, () => APPLYING.has(card));
    hint = box.hint;
    foot.append(wideWhy(s.overBroadWhy, false), box.input);
  }
  const actions = el('div', { class: 'ask-actions' });
  actions.append(discard, apply);
  foot.append(actions);
  if (hint) foot.append(hint);
  card.append(foot);
  host.append(card);
  return first;
}

/** Discard on a suggestion: "Suggestion discarded." with Undo in its place
 *  (dashboard.md §4.25n *Describe can undo its Discard*), as Discard and Drop
 *  in Changes to save leave. The answer, slow and an outside model call, is
 *  kept in page memory (D.discarded) until Suggest rules is pressed again or
 *  an Apply works. A press made with the focus on Discard gives it to Undo. */
function describeDiscarded(s) {
  const host = document.getElementById('describe-result');
  const had = host.contains(document.activeElement);
  D.discarded = s;
  clear(host);
  const line = el('div', { class: 'describe-done', id: 'describe-done' });
  const undo = noticeUndo(line, 'Describe what you want', describeUndoDiscard);
  undo.setAttribute('aria-label', 'Undo the discard in Describe what you want');
  line.append(noticeWords(line, 'Suggestion discarded.'), undo);
  host.append(line);
  if (had) undo.focus({ preventScroll: true });
}
/** Undo of a Discard: the same suggestion drawn again, as it came (its ALLOW
 *  box empty, Apply off for a wide change), and nothing posted; Apply then
 *  goes to the server as before, which refuses it if the rules changed
 *  meanwhile (409). A press made with the focus gives it to the first line,
 *  Suggested rules, as a new answer does. */
function describeUndoDiscard() {
  const s = D.discarded;
  if (!s) return;
  const had = document.getElementById('describe-result').contains(document.activeElement);
  D.discarded = null;
  const first = renderSuggestion(s);
  if (had && first) focusThere(first);
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

/** Suggestion cards whose Apply is out: typing in the ALLOW box leaves
 *  Apply off (`busy` of confirmBox), and Enter does not send it twice. */
const APPLYING = new WeakSet();

/** Apply keeps the focus: applied, the line that says so takes it (the card
 *  is gone); refused, Apply has it back, described by the refusal. Applied
 *  as a change with an id, the line has Undo and a link to that change in
 *  Approvals, as the notice of Your rules does (dashboard.md §4.25 *Every
 *  change made on Rules ends with an Undo or a link*); Undo is off until
 *  Your rules and Rule changes are read again, so it is not pressed over the
 *  reads of the Apply. The answer of an older server, with no id, keeps the
 *  sentence of before. */
async function applySuggestion(s, card) {
  if (APPLYING.has(card)) return;
  APPLYING.add(card);
  const host = document.getElementById('describe-result');
  const applyBtn = [...card.querySelectorAll('button')].find((b) => b.textContent === 'Apply');
  const had = !!applyBtn && document.activeElement === applyBtn;
  for (const b of card.querySelectorAll('button')) b.disabled = true;
  const r = await apiPost('policy/assistant/apply', { edits: s.edits, expected: s.expected });
  if (r.ok) {
    RULES_READS.wrote();
    D.discarded = null;
    clear(host);
    const changeId = r.data ? r.data.changeId : null;
    const link = changesLink(changeId, 'See it in Approvals');
    const done = el('div', { class: 'describe-done', id: 'describe-done' });
    let undo = null;
    if (link) {
      undo = noticeUndo(done, 'Describe what you want', () => undoApplied(done, changeId));
      undo.disabled = true;
      done.append(noticeWords(done, 'Applied. Your rules are updated.'), undo, link);
    } else {
      done.textContent = 'Applied. Your rules are updated, and you can undo this under Rule changes in Approvals.';
    }
    host.append(done);
    if (had && focusFell()) focusThere(done);
    try {
      await loadRules();
      await loadRuleHistory();
    } finally {
      if (undo) undo.disabled = false;
    }
    return;
  }
  APPLYING.delete(card);
  for (const b of card.querySelectorAll('button')) b.disabled = false;
  // A wide change keeps its typed confirmation after a failed Apply.
  const confirm = card.querySelector('.proposal-confirm');
  if (confirm && applyBtn) applyBtn.disabled = !typedAllow(confirm.value);
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

/** Undo on the line of an Apply: the same undo as the row of the change under
 *  Rule changes in Approvals. The line then says "Undone." or the refusal,
 *  and takes the focus if the press left it on the page (the button gone),
 *  as after Apply; Your rules is read again, as its notice does. */
async function undoApplied(done, changeId) {
  const had = done.contains(document.activeElement);
  for (const b of done.querySelectorAll('button')) b.disabled = true;
  const r = await apiPost('policy/changes/' + encodeURIComponent(changeId) + '/undo');
  clear(done);
  done.append(noticeWords(done, r.ok ? 'Undone.' : refusalText(r, 'could not undo (' + r.status + ')')));
  if (had && focusFell()) focusThere(done);
  if (!r.ok) return;
  RULES_READS.wrote();
  await loadRules();
  await loadRuleHistory();
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
  if (btn) btn.disabled = true;
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
  // A turn's address named a turn before those drawn (goToTurn).
  if (land.kind === 'turn') return goToTurn(land.turn, false);
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
  // The earlier turns a secret's line asked for: back to that line.
  else if (land.kind === 'secret') to = document.getElementById('agent-secret-only');
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
 *  no time gets an empty span, which starts no day (storyDayLines). With
 *  `turnId`, its words are the link to that turn (turnLink), inside the
 *  <time>. */
function turnTime(ts, turnId) {
  const ms = ts ? Date.parse(ts) : NaN;
  if (!Number.isFinite(ms)) return el('span', { class: 'time' });
  const at = hhmm(ts);
  return el('time', { class: 'time', datetime: ts, title: clockWords(ms) }, turnId ? turnLink(turnId, at) : at);
}
/** The link a turn's time is (§4.25 *A turn's time links to that turn*):
 *  `/agents/<id>?turn=<turn id>`, ids only, named "Link to this turn,
 *  10:24". A plain click works as a fragment link does: the address becomes
 *  the turn's (replaced, no new entry) and the turn is marked (markTurn);
 *  with a modifier or the middle button, the browser does what it does
 *  with a link (a new tab, a copy). */
function turnLink(turnId, at) {
  return el('a', { class: 'turn-link', href: routeHref('agent', S.agentId, null, null, turnId), 'aria-label': 'Link to this turn, ' + at, onclick: (e) => {
    if (e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    S.agentTurn = turnId;
    history.replaceState(history.state, '', stateHref());
    markTurn(document.getElementById('agent-story'));
  } }, at);
}
/** The accent edge on the turn the address names (`S.agentTurn`), drawn
 *  again with every draw of the story, so a poll keeps it; at most one.
 *  Compared as values, never spliced into a selector. The turn, or null. */
function markTurn(story) {
  for (const t of story.querySelectorAll('article.turn.shown')) t.classList.remove('shown');
  const turn = S.agentTurn ? storyTurns(story).find((t) => t.dataset.turnId === S.agentTurn) : null;
  if (turn) turn.classList.add('shown');
  return turn || null;
}
/** A turn card's heading (§4.25 *Each turn and each secret card is a
 *  heading*): its line ("You asked") as an h3 that names `card`, so a screen
 *  reader moves from turn to turn by heading. Its time is said, not shown
 *  again (" at 20:24"; storyDayLines adds the day when the story spans two). */
let turnTitleSeq = 0;
function turnTitle(card, words, ts) {
  const id = 'turn-title-' + (++turnTitleSeq);
  card.setAttribute('aria-labelledby', id);
  const at = ts ? hhmm(ts) : '';
  return el('h3', { class: 'turn-title', id }, el('span', { class: 'note', text: words }),
    el('span', { class: 'sr-only turn-when', text: at ? ' at ' + at : '' }));
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
  const timed = [];
  let last = null;
  for (const card of [...story.children]) {
    if (!card.matches('article.turn')) continue;
    const t = card.querySelector('.turn-head > time.time');
    const ms = t ? Date.parse(t.getAttribute('datetime')) : NaN;
    if (!Number.isFinite(ms)) continue;
    const day = localDay(ms);
    timed.push({ card, day, at: t.textContent });
    if (day.key !== last) firsts.push({ card, day });
    last = day.key;
  }
  const days = new Set(firsts.map((f) => f.day.key)).size > 1;
  // Each turn's heading says its time; over two days, its day too, the
  // words of the day line above it ("You asked at 00:10 on Friday, Oct 17").
  for (const { card, day, at } of timed) {
    const when = card.querySelector('.turn-title .turn-when');
    if (when) when.textContent = ' at ' + at + (days ? ' on ' + day.words : '');
  }
  if (!days) return;
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
 *  last; "ended" means not running (a recorded exit, or no event for the
 *  running window with no live launch of the session, dashboard.md §4.10.4). A
 *  moment the session did not record is left out, never a bare "ended".
 *  Running, it names its last step as a Running now row does (lastStepMs):
 *  "last step 2 minutes ago" in `.agent-last`, which drawLatestTurn makes a
 *  button to the newest turn when Latest turn shows (lastStepGoes). */
function agentWhenParts(vm) {
  const start = vm.startedAt ? Date.parse(vm.startedAt) : NaN;
  const end = vm.lastAt ? Date.parse(vm.lastAt) : NaN;
  if (vm.running) {
    if (!Number.isFinite(start)) return ['running now'];
    const ms = lastStepMs(vm);
    if (!Number.isFinite(ms)) return ['running now, started ', whenNode(start)];
    return ['running now, started ', whenNode(start), ', ', el('span', { class: 'when-phrase agent-last' }, 'last step ', agoNode(ms))];
  }
  const parts = [];
  const ran = Number.isFinite(start) && Number.isFinite(end) ? spanWords(end - start) : '';
  if (ran) parts.push(el('span', { class: 'agent-ran', title: 'From its first recorded step (' + clockWords(start) + ') to its last.', text: 'ran ' + ran }), ', ');
  if (Number.isFinite(end)) parts.push('ended ', whenNode(end));
  else if (Number.isFinite(start)) parts.push('started ', whenNode(start));
  return parts;
}

/** The session page's tab title (dashboard.md §4.25, *A session page's tab
 *  names its session*): the agent, the last name of its folder ("~" for the
 *  home folder itself) and when it started, as the header line says them
 *  beside the name: "Mandu · Claude Code in shop · Oct 24, 14:05". Without
 *  a start, its last step's moment; with neither, no moment. The moment is
 *  absolute (clockWords), so a running session's title stays as it is. Never
 *  the prompt: the title shows in the window switcher and the browser's
 *  history. */
function sessionTitle(vm) {
  let words = 'Mandu · ' + vm.agent;
  const short = shortPath(vm.cwd);
  const folder = short === '~' ? '~' : short.split('/').filter(Boolean).pop() || short;
  if (folder) words += ' in ' + folder;
  const at = [vm.startedAt, vm.lastAt].map((t) => (t ? Date.parse(t) : NaN)).find(Number.isFinite);
  if (at !== undefined) words += ' · ' + clockWords(at);
  return words;
}

/** The rule changes the agent of this session asked for that wait in
 *  Approvals (the server gives a request its session only when an agent
 *  asked, never for a held change to policy.yaml). */
function agentChanges(id) {
  return S.proposals.filter((p) => !p.onDisk && p.session === id);
}

function renderAgentPage(vm, id, failure, asked) {
  // Printing (printOpen): the read is asked again once the print is done.
  if (S.printOpened) {
    S.printSkipped = true;
    return;
  }
  // A poll that brings the page it shows leaves it as it is (sameAsDrawn):
  // where you scrolled, what you opened, the words of an answer. A new visit
  // draws it afresh. A rule change of this agent that a poll brings or takes
  // away draws it again too. The protection-off line follows what runs now
  // even then: its link to Settings goes once protection is back on.
  if (sameAsDrawn('agent', [S.visit, id, failure, vm, agentChanges(id).map((p) => p.id)])) { renderAgentOff(vm); return; }
  // Drawn again (the agent did more): the focus goes back to its place
  // (pollPlace).
  const place = pollPlace(document.getElementById('page-agent'));
  // A focus in a turn the switch folds goes to the line it folds into
  // (quietRefocus), never the heading.
  const inTurn = place && document.activeElement.closest('#agent-story article.turn[data-turn-id]');
  const turnId = inTurn ? inTurn.dataset.turnId : null;
  drawAgentPage(vm, id, failure);
  // Back to the page: once drawn, where you were (agentLandPlace).
  const kept = S.agentPlace && S.agentPlace.visit === S.visit && S.agentPlace.id === id ? S.agentPlace : null;
  if (kept) {
    S.agentPlace = null;
    agentLandPlace(kept);
    return;
  }
  if (landGo(vm)) return;
  if (!landAgent(asked) && !quietRefocus(turnId)) pollRefocus(place);
}
/** A link that opened the agent page somewhere (`?go=`, a Home count's;
 *  §4.25 *A tile takes you to what it counts*): after the visit's first
 *  draw, once, its blocked or sent tile is pressed (goToOutcome, with the
 *  Show them read for a step in a turn not drawn), Your secrets or Changes
 *  Mandu did not apply to your files takes the focus, the newest turn does as a press of Latest turn gives it (the
 *  "last step" of a Running now row, goToLatestTurn, its button shown or
 *  not), or Needs your OK does as its waiting tile gives it (the "1
 *  question waiting for you" of a row, goToWaiting: its first card, else
 *  its heading). With nothing to go to (no such tile, card, turn or block
 *  shown), the page stays as a plain link opens it. True when it went
 *  somewhere. */
function landGo(vm) {
  const go = S.agentGo;
  if (!go || go.visit !== S.visit) return false;
  S.agentGo = null;
  if (!vm || !vm.found) return false;
  if (go.kind === 'latest') return goToLatestTurn();
  if (go.kind === 'turn') return goToTurn(go.turn, vm.earlier > 0 && vm.allTurns !== true);
  if (go.kind === 'waiting') {
    const block = document.getElementById('agent-waiting-block');
    if (!block || block.hidden) return false;
    goToWaiting();
    return true;
  }
  if (go.kind === 'secrets' || go.kind === 'not-applied') {
    const block = document.getElementById(go.kind === 'secrets' ? 'agent-secrets-block' : 'agent-discarded-block');
    if (!block || block.hidden) return false;
    focusHeading(block);
    if (block.scrollIntoView) block.scrollIntoView({ block: 'start' });
    return true;
  }
  const tile = [...document.querySelectorAll('#agent-facts button.tile[data-goes]')].find((b) => b.dataset.goes === go.kind);
  if (!tile) return false;
  tile.click();
  return true;
}
/** What the counts mean (dashboard.md §4.25 *What the counts mean*): the
 *  fold under a session's tiles, a term and its meaning for each tile drawn
 *  that has one (`[term, meaning]`), as Rules' What the words mean. Closed
 *  until opened; a redraw keeps it as you left it. None: hidden. */
/** Needs your OK on a session page: the questions of this agent, in the
 *  page's order, each in full, or on a phone short with What each answer
 *  does as on Approvals (renderAsks' 'agent' mode; dashboard.md §4.25 *A
 *  waiting question is short on a phone*). Kept (S.agentWaitingShown) so a
 *  flip of the breakpoint draws it again (phoneFlipped). */
function drawAgentWaiting(vm, id) {
  S.agentWaitingShown = { visit: S.visit, id, vm };
  // A rule change this agent asked for waits in Approvals, and the list
  // links it as Home does (dashboard.md §4.25 *A rule change and the agent
  // that asked*).
  // With one, the link opens Approvals at it (§4.25 *Details*).
  const changes = agentChanges(id);
  const wb = document.getElementById('agent-waiting-block');
  // The line an answer left keeps it shown (answerLine).
  wb.hidden = vm.waiting.length === 0 && changes.length === 0 && !hasAnswerLine('agent');
  const waitingHost = document.getElementById('agent-waiting');
  renderAsks(waitingHost, { waitingKnown: true, waiting: vm.waiting }, true, changes.length > 0, 'agent');
  if (changes.length) {
    waitingHost.append(proposalsLink(changes, { class: 'more',
      text: n(changes.length, 'rule change this agent asked for is', 'rule changes this agent asked for are') + ' in Approvals' }));
  }
  // Drawn again while the agent works: each card gets the words of its last
  // answer back (the rows of the note under your message, once the story is).
  putBackAnswers('agent', waitingHost);
}
function drawCountMeanings(meanings) {
  const fold = document.getElementById('agent-count-meanings');
  if (!fold) return;
  const list = fold.querySelector('dl');
  clear(list);
  for (const [term, says] of meanings) list.append(el('dt', { text: term }), el('dd', { text: says }));
  fold.hidden = meanings.length === 0;
}
function drawAgentPage(vm, id, failure) {
  const name = document.getElementById('agent-name');
  const sub = document.getElementById('agent-sub');
  const facts = document.getElementById('agent-facts');
  const story = document.getElementById('agent-story');
  const trace = document.getElementById('agent-trace');
  trace.href = DEV_URL + 'sessions/' + encodeURIComponent(id);
  // Drawn again in the same visit (the agent did more): the toggles of the
  // story go back as you left them. Its first draw after a Back: as the
  // entry kept them (savePlace).
  const kept = S.agentPlace && S.agentPlace.visit === S.visit && S.agentPlace.id === id ? S.agentPlace.place.story : null;
  const again = S.agentDrawn === S.visit + ':' + id;
  const left = again ? storyToggles(story) : kept;
  S.agentDrawn = S.visit + ':' + id;
  // The replies drawn before go: their folds are measured no more.
  if (replySizes) replySizes.disconnect();
  stopHidesLater();
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
      // An old link, a bookmark, a session past its 90 days: say so in the
      // page's words and lead to History, where past sessions are found.
      name.textContent = 'Session not found';
      sub.append('Mandu has no record of this session. Records are kept for 90 days, so it may be older than that, or the link may be wrong. Look for it in ',
        placeLink({ text: 'History', to: 'history' }), '.');
    }
    const valuesNote = document.getElementById('agent-values-note');
    if (valuesNote) valuesNote.hidden = true;
    S.agentWaitingShown = null;
    document.getElementById('agent-waiting-block').hidden = true;
    clear(document.getElementById('agent-waiting'));
    putBackAnswers('agent', document.getElementById('agent-waiting'));
    putBackAnswers('note', story);
    renderAgentNotice(null);
    renderAgentOff(null);
    renderAgentPosture(null);
    renderAgentSecrets(null);
    renderReadAsIs(null, false);
    renderDiscardedWrites(null);
    renderAgentBrowser(null);
    renderAgentFinding(null);
    drawCountMeanings([]);
    drawOnlySwitch(null);
    drawLatestTurn(null);
    renderAgentNeighbours(null);
    storyBlock.hidden = true;
    return;
  }
  storyBlock.hidden = false;
  name.textContent = vm.agent;
  // The tag and the warning mark by the name, in its Home row's order.
  if (vm.preview) name.append(' ', agentPreviewMark(vm.preview));
  if (vm.notice) name.append(' ', agentNoticeMark(vm.notice, vm.noticeParts));
  renderAgentNotice(vm);
  renderAgentOff(vm);
  renderAgentPosture(vm);
  // Signed out, the page shows only what the AI saw (dashboard.md §6).
  S.valuesShown = vm.valuesShown !== false;
  const valuesNote = document.getElementById('agent-values-note');
  if (valuesNote) {
    valuesNote.hidden = S.valuesShown;
    setWords(valuesNote, SIGN_IN_VALUES);
  }
  S.pageTitle = sessionTitle(vm);
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
  // How long Mandu took to start the session, its slowest steps first, and
  // to clean up after it (dashboard.md §4.25ag; the server's words).
  if (vm.launchTime) {
    const lt = vm.launchTime;
    sub.append(el('div', { class: 'dim agent-launch-time', style: 'font-size:14px;margin-top:2px', text: lt.sentence + (lt.cleanup ? ' ' + lt.cleanup : '') }));
  }

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
  // A tile's tooltip is what it counts (COUNT_MEANINGS), then where the
  // page shows it (`where`), or the press (`press`). What the counts mean,
  // under the tiles, lists each drawn tile's meaning and where, never the
  // press: the tooltip of a phone or a keyboard (dashboard.md §4.25 *What
  // the counts mean*).
  const meanings = [];
  const meant = (kind, k, where, press) => {
    const says = [COUNT_MEANINGS[kind].means(k), where].filter(Boolean).join(' ');
    meanings.push([COUNT_MEANINGS[kind].term, says]);
    return press ? says + ' ' + press : says;
  };
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
        meant('masked', masked, 'Your secrets, below, names them.')));
    }
    if (early) {
      facts.append(tile(early, early === 1 ? 'secret the AI read before it was marked a secret' : 'secrets the AI read before they were marked secrets', 'warn',
        meant('early', early, 'Your secrets, below, says when.')));
    }
  }
  if (untrusted) facts.append(tile(untrusted, untrusted === 1 ? 'untrusted item masked before the AI saw it' : 'untrusted items masked before the AI saw them'));
  const blockedGoes = vm.blocked ? reach('blocked') : null;
  facts.append(tile(vm.blocked, vm.blocked === 1 ? 'action blocked' : 'actions blocked', '',
    meant('blocked', vm.blocked, blockedGoes ? null : 'What happened, below, shows it.', blockedGoes ? (vm.blocked === 1 ? 'Press to go to it under What happened.' : 'Press to go to each in turn under What happened.') : null),
    blockedGoes));
  if (vm.sent) {
    const sentGoes = reach('sent');
    facts.append(tile(vm.sent, vm.sent === 1 ? 'send with a real value filled in' : 'sends with a real value filled in', '',
      meant('sent', vm.sent, sentGoes ? null : 'What happened, below, shows where.', sentGoes ? (vm.sent === 1 ? 'Press to go to it under What happened.' : 'Press to go to each in turn under What happened.') : null),
      sentGoes));
  }
  if (vm.waiting.length) facts.append(tile(vm.waiting.length, 'waiting for you', 'warn', 'Press to go to Needs your OK, below.', 'waiting'));
  drawCountMeanings(meanings);
  // What the leak check found, under the tiles (dashboard.md §4.25ae).
  renderAgentFinding(vm.finding || null);
  // The sessions above and below this one in History (§4.25b *Newer and
  // older sessions*), after What happened.
  renderAgentNeighbours(vm.neighbours || null);

  drawAgentWaiting(vm, id);

  renderAgentSecrets(vm.secrets, vm.allSecrets === true);
  renderReadAsIs(vm.readAsIs || null, again);
  renderDiscardedWrites(vm.discardedWrites || null);
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
  markTurn(story);
  // A message Mandu stopped never reached the AI, so no turn shows it: its
  // note goes in the story by its time (plan 15 §13.7).
  for (const note of vm.unplacedNotes || []) {
    const card = el('article', { class: 'turn prompt-unsent' });
    card.append(el('div', { class: 'turn-head' }, turnTime(note.ts),
      el('div', { class: 'turn-q' }, turnTitle(card, 'A message you wrote', note.ts), promptNoteNode(note))));
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
  drawLatestTurn(story);
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

// ── Latest turn (dashboard.md §4.25ad) ──────────────────────────────────────
/** The turn cards drawn, oldest first: not the messages Mandu stopped,
 *  which are no turn. */
function storyTurns(story) {
  return story ? [...story.querySelectorAll('article.turn[data-turn-id]')] : [];
}
/** The link beside the switch: shown from three turns drawn (the earlier
 *  ones not drawn do not count), its words naming the newest turn's time as
 *  its card says it (turnTime's words, a day line or not); the arrow is not
 *  in its name. A static button, so a poll redraw only rewrites its words
 *  and a focus on it stays. `story` null: hidden. */
function drawLatestTurn(story) {
  const btn = document.getElementById('agent-latest');
  const turns = storyTurns(story);
  btn.hidden = turns.length < 3;
  lastStepGoes(!btn.hidden);
  if (btn.hidden) return;
  const t = turns[turns.length - 1].querySelector('.turn-head > time.time');
  const words = 'Latest turn' + (t && t.textContent ? ', ' + t.textContent : '') + ' ';
  if (btn.firstChild.nodeValue !== words) btn.firstChild.nodeValue = words;
}
/** The name of the "last step" button in the header: its words, then where it
 *  goes ("Last step 2 minutes ago: go to the latest turn"). */
function lastStepName(ms) {
  return 'Last step ' + ago(ms) + ': go to the latest turn';
}
/** The "last step" of the header (agentWhenParts) as Latest turn shows: with it
 *  shown, a link-style button that does what Latest turn does; else plain
 *  words, the newest turn already in sight. A `step-link`, so it prints as
 *  its words. */
function lastStepGoes(shown) {
  const at = document.querySelector('#agent-sub .agent-last');
  if (!at) return;
  const btn = at.querySelector('button.agent-last-go');
  if (shown === !!btn) return;
  if (!shown) { btn.replaceWith(...btn.childNodes); return; }
  const t = at.querySelector('time.ago');
  const go = el('button', { type: 'button', class: 'step-link agent-last-go', 'aria-label': lastStepName(Date.parse(t.getAttribute('datetime'))), onclick: goToLatestTurn });
  go.append(...at.childNodes);
  at.append(go);
}
/** Latest turn pressed: the newest turn takes the focus (focusThere) and
 *  scrolls to its top; folded into a quiet line by the switch, that line's
 *  button does, never a hidden card. The page never goes there by itself,
 *  only when a link asks (`?go=latest`, landGo). False with no turn drawn. */
function goToLatestTurn() {
  const turn = storyTurns(document.getElementById('agent-story')).pop();
  if (!turn) return false;
  goToCard(turn);
  return true;
}
/** A turn card takes the focus (focusThere) and scrolls to its top; folded
 *  into a quiet line by the switch, that line's button does, never a
 *  hidden card. */
function goToCard(turn) {
  const btn = turn.hidden ? quietButton(turn) : null;
  const to = btn || turn;
  if (btn) btn.focus({ preventScroll: true });
  else focusThere(turn);
  if (to.scrollIntoView) to.scrollIntoView({ block: btn ? 'center' : 'start' });
}
/** A turn's address (`?turn=`, landGo; §4.25 *A turn's time links to that
 *  turn*): that turn, marked by its draw (markTurn), takes the focus as
 *  Latest turn's does (goToCard). One before those drawn (`more`: earlier
 *  turns the page can still ask for) first brings every turn, the Show
 *  them read, and comes back here once it is drawn (landAgent). An id the story does not have: What happened's
 *  heading takes the focus, in view. Always true: it went somewhere. */
function goToTurn(turnId, more) {
  const story = document.getElementById('agent-story');
  // Compared as values, never spliced into a selector: ids are server data.
  const turn = storyTurns(story).find((t) => t.dataset.turnId === turnId);
  if (turn) goToCard(turn);
  else if (more) {
    const btn = story.querySelector(':scope > .story-more:not(.story-quiet) .show-rest');
    showAgentRest(btn, (s) => { s.turns = true; }, { kind: 'turn', turn: turnId });
  } else {
    const block = document.getElementById('agent-story-block');
    focusHeading(block);
    if (block.scrollIntoView) block.scrollIntoView({ block: 'start' });
  }
  return true;
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
  // The switch ends a secret's filter (§4.25b *A card shows its steps*).
  S.agentSecretOnly = null;
  syncSecretButtons();
  foldQuiet(document.getElementById('agent-story'));
}
/** With the switch on, each run of quiet turns folds behind one line ("5
 *  turns where Mandu did nothing") whose button shows them in place; off,
 *  every turn shows. A secret's filter (secretOnly, §4.25b *A card shows its
 *  steps*) takes the switch's place while it is on: each run of the turns
 *  that hold none of its steps folds the same way, its steps are marked,
 *  and its line (secretLine) goes above the story. A turn a fold hides is
 *  `.folded`. A focus the fold hides goes to its line's button. */
let quietSeq = 0;
function foldQuiet(story) {
  const had = document.activeElement;
  for (const line of story.querySelectorAll('.story-quiet, .story-secret')) line.remove();
  for (const t of story.querySelectorAll('article.turn.folded')) {
    t.classList.remove('folded', 'unused');
    t.removeAttribute('hidden');
  }
  for (const x of story.querySelectorAll('.secret-kept, .secret-at')) x.classList.remove('secret-kept', 'shown', 'secret-at');
  const only = secretOnly();
  if (!only) S.agentSecretOnly = null;
  if (!only && !S.agentOnly) return;
  if (only) {
    const kept = new Set(only.turns || []);
    const steps = new Set(only.steps);
    // Compared as values, never spliced into a selector: ids are server data.
    for (const t of story.querySelectorAll('article.turn[data-turn-id]')) if (!kept.has(t.dataset.turnId)) t.classList.add('unused');
    for (const x of story.querySelectorAll('[data-step-id]')) if (steps.has(x.dataset.stepId)) x.classList.add('shown', 'secret-kept');
    // The step Next step last went to keeps its mark while it is drawn.
    const at = secretDrawn(story, only).find((x) => x.dataset.stepId === S.agentSecretOnly.at);
    if (at) {
      at.classList.add('secret-at');
      at.setAttribute('tabindex', '-1');
    } else S.agentSecretOnly.at = null;
    story.prepend(secretLine(story, only));
  }
  const folds = only ? 'article.turn.unused' : 'article.turn.quiet';
  let run = [];
  const flush = () => {
    if (run.length) quietLine(run, !!only);
    run = [];
  };
  for (const x of [...story.children]) {
    if (x.matches(folds)) run.push(x);
    else flush();
  }
  flush();
  const turn = had && had.isConnected && had.closest('#agent-story article.turn.folded');
  if (turn && turn.hidden) quietButton(turn).focus({ preventScroll: true });
}
function quietLine(run, secret) {
  const count = run.length;
  const show = count === 1 ? 'Show it' : 'Show them';
  const hide = count === 1 ? 'Hide it' : 'Hide them';
  // Keyed by its first turn (data-quiet-from), as the poll finds it again.
  const line = el('div', { class: 'story-more story-quiet', 'data-quiet-from': run[0].dataset.turnId });
  // A secret's fold says what Mandu found, never that the turns did not use it.
  const said = el('span', { id: 'quiet-' + (++quietSeq), text: n(count, 'turn', 'turns') + (secret ? ' where Mandu found no step of this secret' : ' where Mandu did nothing') });
  const btn = el('button', { type: 'button', class: 'btn small show-rest quiet-toggle', 'aria-expanded': 'false', 'aria-describedby': said.id, text: show });
  btn.addEventListener('click', () => {
    const open = btn.getAttribute('aria-expanded') !== 'true';
    for (const t of run) foldFindable(t, !open);
    btn.setAttribute('aria-expanded', String(open));
    btn.textContent = open ? hide : show;
  });
  for (const t of run) {
    t.classList.add('folded');
    foldFindable(t, true);
  }
  line.append(said, ' ', btn);
  run[0].before(line);
}
/** The button of the line a folded turn is behind (the line sits just
 *  before the run's first turn). */
function quietButton(turn) {
  let x = turn.previousElementSibling;
  while (x && x.matches('article.turn.folded')) x = x.previousElementSibling;
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

// ── A card shows its steps (dashboard.md §4.25b) ────────────────────────────
/** A Your secrets card's key: its level and its name, as the server groups
 *  its secrets (secret-story.ts), the same across a poll. */
function secretKey(s) { return JSON.stringify([s.level, s.what]); }
/** The card whose filter is on, as last drawn, or null: none pressed this
 *  visit of this page, or its card is gone or has no step now. */
function secretOnly() {
  const on = S.agentSecretOnly;
  if (!on || on.visit !== S.visit || on.id !== S.agentId) return null;
  const card = S.agentSecretCards.find((x) => secretKey(x) === on.key);
  return card && Array.isArray(card.steps) && card.steps.length ? card : null;
}
/** A card's name inside a sentence: its heading's words, the first one in
 *  lower case ("the environment variable `STRIPE_KEY`"). */
function secretNameParts(what) {
  const parts = what.map((p) => ({ ...p }));
  if (parts[0] && parts[0].kind === 'text') parts[0].text = parts[0].text.charAt(0).toLowerCase() + parts[0].text.slice(1);
  return parts;
}
/** The line above the story while a secret's filter is on: how many drawn
 *  turns Mandu found a step of it in, how many earlier turns not drawn have
 *  one (with the earlier turns' Show them, or that they are past what the
 *  page shows), *Previous step* and *Next step* with where the last press
 *  went (goToSecretStep; only with two or more of its steps drawn), and
 *  *Show every turn*. Its words claim only what Mandu found, never every
 *  step. `#agent-secret-only`. */
function secretLine(story, card) {
  const line = el('div', { class: 'story-more story-secret', id: 'agent-secret-only' });
  line.append(...secretWords(card).childNodes);
  const earlier = card.earlierTurns || 0;
  if (earlier) {
    const rest = story.querySelector(':scope > .story-more:not(.story-quiet):not(.story-secret) .show-rest');
    if (rest) {
      line.append(' ' + n(earlier, 'earlier turn not shown here has one too.', 'earlier turns not shown here have one too.') + ' ');
      line.append(el('button', { type: 'button', class: 'btn small secret-earlier-turns', text: earlier === 1 ? 'Show it' : 'Show them',
        onclick: (e) => showAgentRest(e.currentTarget, (x) => { x.turns = true; }, { kind: 'secret' }) }));
    } else line.append(' ' + n(earlier, 'earlier turn past what this page shows has one too.', 'earlier turns past what this page shows have one too.'));
  }
  // Never .show-rest: goToTurn finds the earlier turns' button by it.
  const drawn = secretDrawn(story, card);
  if (drawn.length > 1) {
    const i = drawn.findIndex((x) => x.dataset.stepId === S.agentSecretOnly.at);
    line.append(' ', el('button', { type: 'button', class: 'btn small secret-prev', text: 'Previous step', onclick: () => goToSecretStep(-1) }),
      ' ', el('button', { type: 'button', class: 'btn small secret-next', text: 'Next step', onclick: () => goToSecretStep(1) }),
      ' ', el('span', { class: 'secret-where', text: i === -1 ? '' : secretWhere(i, drawn.length) }));
  }
  line.append(' ', el('button', { type: 'button', class: 'btn small secret-all', text: 'Show every turn', onclick: () => endSecretOnly(true) }));
  return line;
}
/** The steps of `card` the story draws now, in page order (a step in a
 *  folded run of steps counts; one in a turn not drawn does not). Ids are
 *  compared as values, never spliced into a selector. */
function secretDrawn(story, card) {
  const steps = new Set(card.steps);
  return [...story.querySelectorAll('[data-step-id]')].filter((x) => steps.has(x.dataset.stepId));
}
/** "Step 2 of 7": the `i`th of `of` drawn steps. */
function secretWhere(i, of) { return 'Step ' + (i + 1) + ' of ' + of; }
/** *Next step* (`dir` 1) or *Previous step* (-1) on a secret's line: the
 *  card's drawn step after (before) the one the last press went to, after
 *  the last the first (from none, the first or the last), through showStep
 *  (its fold opened, focused, in view). That one step gets `.secret-at` on
 *  top of the filter's marks, and the line and the polite status say where
 *  it is ("Step 2 of 7"). The place is the filter's (`S.agentSecretOnly.at`):
 *  it ends with it, and a poll keeps it while its step is drawn (foldQuiet). */
function goToSecretStep(dir) {
  const on = S.agentSecretOnly;
  const card = secretOnly();
  const story = document.getElementById('agent-story');
  if (!card || !story) return;
  const steps = secretDrawn(story, card);
  if (!steps.length) return;
  const i = steps.findIndex((x) => x.dataset.stepId === on.at);
  const j = i === -1 ? (dir > 0 ? 0 : steps.length - 1) : (i + dir + steps.length) % steps.length;
  const to = steps[j];
  on.at = to.dataset.stepId;
  for (const x of story.querySelectorAll('.secret-at')) x.classList.remove('secret-at');
  to.classList.add('secret-at');
  showStep(on.at);
  const where = secretWhere(j, steps.length);
  const words = document.querySelector('#agent-secret-only .secret-where');
  if (words) words.textContent = where;
  storyStatus(where);
}
/** "Showing the 4 turns where Mandu found a step of the environment
 *  variable `STRIPE_KEY`." (a node whose children are the words). */
function secretWords(card) {
  const name = secretNameParts(card.what);
  const shown = (card.turns || []).length;
  return sentenceNode(shown
    ? [{ kind: 'text', text: 'Showing the ' + n(shown, 'turn', 'turns') + ' where Mandu found a step of ' }, ...name, { kind: 'text', text: '.' }]
    : [{ kind: 'text', text: 'Mandu found no step of ' }, ...name, { kind: 'text', text: ' in the turns shown here.' }], '');
}
/** What the story's polite status says (`#agent-story-status`). */
function storyStatus(text) {
  const status = document.getElementById('agent-story-status');
  if (status) status.textContent = text;
}
/** Each card's Show its steps says what a press does now: *Show every
 *  turn* on the card whose filter is on. */
function syncSecretButtons() {
  const on = secretOnly();
  const key = on ? secretKey(on) : null;
  for (const b of document.querySelectorAll('#agent-secrets .secret-steps')) b.textContent = b.dataset.key === key ? 'Show every turn' : 'Show its steps';
}
/** Show its steps pressed on card `s`: the story keeps only the turns that
 *  hold its steps (foldQuiet), the line above it takes the focus, and the
 *  status says the same. Pressed on the card whose filter is on: every turn
 *  again, the focus staying on the button. */
function pressSecretSteps(s) {
  const on = secretOnly();
  if (on && secretKey(on) === secretKey(s)) { endSecretOnly(false); return; }
  S.agentSecretOnly = { visit: S.visit, id: S.agentId, key: secretKey(s), at: null };
  syncSecretButtons();
  foldQuiet(document.getElementById('agent-story'));
  const line = document.getElementById('agent-secret-only');
  if (!line) return;
  // The line's words, without its buttons.
  storyStatus([...line.childNodes].filter((x) => x.nodeName !== 'BUTTON').map((x) => x.textContent).join('').replace(/\s+/g, ' ').trim());
  landOn(line);
}
/** The secret's filter ends: the story as the switch has it (foldQuiet),
 *  and the status says so. `back`: the focus goes to the card's button (the
 *  line's *Show every turn* is gone with the line). */
function endSecretOnly(back) {
  const on = secretOnly();
  S.agentSecretOnly = null;
  syncSecretButtons();
  foldQuiet(document.getElementById('agent-story'));
  storyStatus(S.agentOnly ? 'Showing the turns where Mandu stepped in.' : 'Showing every turn.');
  if (!back || !on) return;
  const btn = [...document.querySelectorAll('#agent-secrets .secret-steps')].find((b) => b.dataset.key === secretKey(on));
  if (btn) {
    btn.focus({ preventScroll: true });
    if (btn.scrollIntoView) btn.scrollIntoView({ block: 'center' });
  }
}
/** Opens the folded run that holds `x`, if one does (a step a link shows,
 *  the turn a Show them brought). */
function openQuiet(x) {
  const turn = x && x.closest('article.turn.folded');
  const btn = turn && turn.hidden ? quietButton(turn) : null;
  if (btn) btn.click();
}
/** Opens the run of steps that holds `x` through its button, if one is
 *  folded (the button of each fold is in the row right after it, as
 *  showStep, landAgent and markFocus find it). */
function openSteps(x) {
  const fold = x && x.closest('.steps-more');
  if (!fold || !fold.hidden) return;
  const btn = fold.nextElementSibling && fold.nextElementSibling.querySelector('.steps-toggle');
  if (btn) btn.click();
}

// ── Find in page (dashboard.md §4.25b, *Find in page opens a fold*) ─────────
/** Folds `x` away (`folded`) or shows it. Folded, it is
 *  `hidden="until-found"`: drawn as nothing, but Find in page (Ctrl+F)
 *  still searches it and, on a match, opens it (findOpens). A browser
 *  without it treats it as plain `hidden`. Set as an attribute: the `hidden`
 *  property is a plain boolean in some browsers. */
function foldFindable(x, folded) {
  if (folded) x.setAttribute('hidden', 'until-found');
  else x.removeAttribute('hidden');
}
/** The browser is about to open a fold of the story for a match of its
 *  Find, a text fragment or a link (`beforematch`, fired at each fold that
 *  holds the match, before the browser shows it). The fold opens through
 *  its button, as a press would: its words and `aria-expanded` follow, a
 *  quiet run opens whole, and a poll keeps it open (storyToggles). */
function findOpens(e) {
  const x = e.target;
  if (!x || !x.closest) return;
  openQuiet(x);
  openSteps(x);
}

// ── A printed session is whole (dashboard.md §4.25b, *A printed session is whole*) ──
/** Just before the browser prints the agent page (Ctrl+P, Save as PDF),
 *  every folded run of steps, every long reply, every clipped question or
 *  output and every file list of the story opens, and What the counts mean, each through its own
 *  control, so its words and `aria-expanded` follow; just after, what this
 *  opened folds again and the screen is as it was (`S.printOpened`, the way
 *  back of each). A fold you opened stays open. What the switch folds stays
 *  folded (anything under a `[hidden]` turn is left as it is), and nothing
 *  asks the server: no reveal, no "Show them", so a value hidden on screen
 *  stays hidden on paper. app.css's print styles drop the controls. The
 *  page draws nothing in between (renderAgentPage), and a read that came
 *  meanwhile is asked again after. */
function printOpen() {
  if (S.printOpened) return;
  S.printOpened = [];
  if (S.page !== 'agent') return;
  const story = document.getElementById('agent-story');
  // A secret's filter (§4.25b *A card shows its steps*) prints every turn:
  // its folded runs open, and fold again after.
  if (secretOnly()) {
    for (const btn of story.querySelectorAll('.story-quiet .quiet-toggle[aria-expanded="false"]')) {
      btn.click();
      S.printOpened.push(() => { if (btn.getAttribute('aria-expanded') === 'true') btn.click(); });
    }
  }
  const folded = (sel) => [...story.querySelectorAll(sel)].filter((x) => !x.closest('[hidden]'));
  for (const btn of folded('.steps-toggle[aria-expanded="false"], .linkish[aria-expanded="false"]')) {
    btn.click();
    S.printOpened.push(() => { if (btn.getAttribute('aria-expanded') === 'true') btn.click(); });
  }
  for (const btn of folded('.reply-fold[aria-expanded="false"]')) {
    const toggle = replyToggles.get(btn);
    if (!toggle) continue;
    toggle(true);
    S.printOpened.push(() => toggle(false));
  }
  for (const list of folded('details.files:not([open])')) {
    list.open = true;
    S.printOpened.push(() => { list.open = false; });
  }
  // What the counts mean, under the tiles, prints open too.
  const meanings = document.getElementById('agent-count-meanings');
  if (meanings && !meanings.hidden && !meanings.open) {
    meanings.open = true;
    S.printOpened.push(() => { meanings.open = false; });
  }
}
function printClose() {
  const opened = S.printOpened;
  S.printOpened = null;
  if (!opened) return;
  for (const back of opened.reverse()) back();
  if (S.printSkipped) {
    S.printSkipped = false;
    if (S.page === 'agent') loadAgent();
  }
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
/** When a neighbour's last moment was, as a clock reads it (dashboard.md
 *  §4.25b *Newer and older sessions*): "14:05" today, "yesterday 22:10",
 *  else clockWords ("Sep 30, 14:12", with the year when not this one). */
function neighbourWhen(ms, nowMs) {
  const now = nowMs === undefined ? Date.now() : nowMs;
  const pad = (k) => String(k).padStart(2, '0');
  const d = new Date(ms);
  const clock = pad(d.getHours()) + ':' + pad(d.getMinutes());
  const day = localDay(ms, now).key;
  if (day === localDay(now, now).key) return clock;
  const t = new Date(now);
  if (day === localDay(new Date(t.getFullYear(), t.getMonth(), t.getDate() - 1, 12).getTime(), now).key) return 'yesterday ' + clock;
  return clockWords(ms, now);
}
/** One link of the line under What happened: "← Newer: Claude Code · Fix the
 *  login test · 14:05" or "Older: Codex · What is in .env? · yesterday
 *  22:10 →", named as its History row (the agent, what you asked, no words
 *  for a fallback label) with the time of its last moment, the clock time
 *  in full on hover. An ordinary page change (wireNav): Back returns here,
 *  a middle click opens a tab. null without a neighbour. */
function neighbourLink(n, side) {
  if (!n || typeof n.id !== 'string' || !n.id) return null;
  const newer = side === 'newer';
  const ms = n.at ? Date.parse(n.at) : NaN;
  const parts = [el('span', { class: 'neighbour-side', text: newer ? 'Newer:' : 'Older:' }), ' ', el('span', { class: 'neighbour-agent', text: n.agent || 'Agent' })];
  if (n.title) parts.push(' · ', el('span', { class: 'neighbour-title', text: n.title }));
  if (Number.isFinite(ms)) parts.push(' · ', el('time', { class: 'neighbour-when', datetime: new Date(ms).toISOString(), title: clockWords(ms), text: neighbourWhen(ms) }));
  const arrow = el('span', { class: 'neighbour-arrow', 'aria-hidden': 'true', text: newer ? '←' : '→' });
  return el('a', { class: 'neighbour ' + side, href: routeHref('agent', n.id), 'data-page-link': 'agent', 'data-session': n.id },
    ...(newer ? [arrow, ' ', ...parts] : [...parts, ' ', arrow]));
}
/** The Newer and Older links at the end of a session's page (dashboard.md
 *  §4.25b *Newer and older sessions*): the sessions just above and below
 *  this one in History's full list, as the server found them; hidden and
 *  empty with neither (the newest has no Newer, the oldest no Older, a
 *  drill or test run and a page not read neither). Drawn again only when
 *  they changed, so a poll leaves a focused link in place. */
function renderAgentNeighbours(n) {
  const nav = document.getElementById('agent-neighbours');
  if (!nav) return;
  const newer = neighbourLink(n && n.newer, 'newer');
  const older = neighbourLink(n && n.older, 'older');
  const key = newer || older ? JSON.stringify([n.newer || null, n.older || null, localDay(Date.now()).key]) : '';
  if (nav.dataset.drawn === key && (key || nav.hidden)) return;
  nav.dataset.drawn = key;
  clear(nav);
  nav.hidden = !(newer || older);
  if (newer) nav.append(newer);
  if (older) nav.append(older);
}

/** Each place a recorded event says something reached the AI without its
 *  mask: when (a time the story shows opens its step), the step's words and
 *  the secrets it held by name. Never the text the check found: a value is
 *  only where the step itself shows one, signed in. */
function renderAgentFinding(f) {
  const block = document.getElementById('agent-finding-block');
  const list = document.getElementById('agent-finding');
  const intro = document.getElementById('agent-finding-intro');
  const todo = document.getElementById('agent-finding-todo');
  clear(list);
  clear(todo);
  if (!f) { block.hidden = true; return; }
  block.hidden = false;
  const places = f.items.length + f.more;
  intro.textContent = places
    ? 'Mandu\'s leak check found ' + n(places, 'place', 'places') + ' where something reached the AI without its mask. Each line says where and when, never the text itself.'
    : 'Mandu\'s leak check flagged this session.';
  for (const item of f.items) list.append(el('li', { class: 'finding-line' }, svg(ICON.alert, 14), sentenceNode(item.parts, '')));
  if (f.more) list.append(el('li', { class: 'finding-line dim', text: n(f.more, 'more place is', 'more places are') + ' past what this page lists.' }));
  // What to do now: change each key it names, and report the fault.
  const steps = f.todo || [];
  todo.hidden = !steps.length;
  document.getElementById('agent-finding-todo-title').hidden = !steps.length;
  for (const parts of steps) todo.append(el('li', { class: 'todo-line' }, sentenceNode(parts, '')));
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
    else {
      // Why it typed nothing, in the cause's words (browser-story.ts
      // `refusalCause`); an unknown cause reads as it always did.
      const lead = 'The agent tried to type ' + t.secret + ' into ' + (t.site || 'a page') + times + ': Mandu typed nothing, because ';
      if (t.why === 'needs-approval') {
        list.append(el('li', { class: 'secret-line warn' }, svg(ICON[SECRET_LINE_ICON.warn], 14),
          el('span', {}, lead + 'that site may get it only with your OK. Answer in ',
            el('a', { href: routeHref('approvals'), 'data-page-link': 'approvals', text: 'Approvals' }), '.')));
      } else if (t.why === 'declined') line('plain', lead + 'you chose Send without it.');
      else if (t.why === 'failed') line('warn', lead + 'it could not check where the value would go.');
      else if (t.why === 'not-allowed') line('bad', lead + 'that site may not receive it.');
      else line('bad', 'The agent tried to type ' + t.secret + ' into a page' + times + ': Mandu typed nothing, because that site may not receive it.');
    }
  }
  for (const s of b.stopped) line('bad', 'Mandu stopped ' + n(s.count, s.what, s.what + 's') + ': ' + (BROWSER_STOP_WHY[s.what] || 'the agent may not use it') + '.');
  if (b.withheld) line('warn', 'Mandu held back ' + n(b.withheld, 'page message', 'page messages') + ' it could not check, so the agent never got ' + (b.withheld === 1 ? 'it.' : 'them.'));
  for (const s of b.services) {
    line('good', 'The agent sent ' + n(s.requests, 'request', 'requests') + ' to ' + s.host + ' itself' +
      (s.masked.length ? ', with ' + names(s.masked) + ' masked in ' + (s.requests === 1 ? 'it' : 'them') : '') + '.');
  }
}
/** "Your secrets" over a record Mandu could not check (dashboard.md
 *  §4.25ah, `story.unchecked`): every report of the session is the agent's
 *  word, so the block never says no secret came up. */
const UNCHECKED_SECRETS_WORDS = ownWords('Mandu could not check this session\'s record: on this computer the agent could reach Mandu\'s own controls, so this page counts no secret from it. Run ', ['mandu doctor', 'run'], ' to see why.');
const UNCHECKED_REST_WORDS = ownWords('Mandu could not check the rest of this session\'s record: on this computer the agent could reach Mandu\'s own controls. Run ', ['mandu doctor', 'run'], ' to see why.');
let secretWhatSeq = 0;
function renderAgentSecrets(story, all) {
  const block = document.getElementById('agent-secrets-block');
  const list = document.getElementById('agent-secrets');
  const intro = document.getElementById('agent-secrets-intro');
  const limits = document.getElementById('agent-secrets-limits');
  clear(list);
  if (!story) { S.agentSecretCards = []; block.hidden = true; return; }
  block.hidden = false;
  const count = story.secrets.length + story.more;
  if (story.unchecked === true) {
    // Never "no secret came up" over a record the agent could have written.
    clear(intro);
    if (count) intro.append(n(count, 'secret you registered or labeled', 'secrets you registered or labeled') + ' came up in this session. Each line below comes from what Mandu recorded. ');
    intro.append(words(count ? UNCHECKED_REST_WORDS : UNCHECKED_SECRETS_WORDS));
  } else {
    intro.textContent = count
      ? n(count, 'secret you registered or labeled', 'secrets you registered or labeled') + ' came up in this session. Each line below comes from what Mandu recorded.'
      : 'No secret you registered or labeled came up in this session.';
  }
  S.agentSecretCards = story.secrets;
  for (const s of story.secrets) {
    // Its name is the card's heading (§4.25 *Each turn and each secret card
    // is a heading*); the level tag stays beside it, not in it.
    const what = el('h3', { class: 'secret-what', id: 'secret-what-' + (++secretWhatSeq) }, ...sentenceNode(s.what, '').childNodes);
    const card = el('div', { class: 'secret-card' },
      el('div', { class: 'secret-head' }, what, secretLevelTag(s)));
    const ul = el('ul', { class: 'secret-lines' });
    for (const line of s.lines) ul.append(el('li', { class: 'secret-line ' + line.tone }, svg(ICON[SECRET_LINE_ICON[line.tone]] || ICON.check, 14), sentenceNode(line.parts, '')));
    card.append(ul);
    appendSecretPath(card, s);
    // Signed in, its real value on a click (never on the page by default),
    // named by the card heading drawn above it.
    if (s.ref && S.valuesShown !== false) card.append(secretValueBox(s.ref, null, card, lineWords(what)));
    // Its file opens in Rules, to change who may read it (§4.25b *A card
    // opens its file in Rules*). A plain link: a new tab, a bookmark, Back.
    const rule = el('div', { class: 'secret-rule' });
    if (typeof s.file === 'string' && s.file) {
      rule.append(el('a', { href: routeHref('rules', s.file), 'data-page-link': 'rules', 'data-file': s.file, class: 'secret-rule-link',
        text: 'Change it in Rules', 'aria-label': 'Change the rule for ' + s.file + ' in Rules' }));
    }
    // Show its steps (§4.25b *A card shows its steps*), on a card with steps
    // on this page: the story keeps only the turns that hold them. The
    // row's gap sets it apart from the link, no text between them.
    if (Array.isArray(s.steps) && s.steps.length) {
      rule.append(el('button', { type: 'button', class: 'btn small secret-steps', 'data-key': secretKey(s), 'aria-describedby': what.id,
        text: 'Show its steps', onclick: () => pressSecretSteps(s) }));
    }
    // Its other sessions (§4.25b *A card finds its other sessions*): History
    // searched for its file, else its key's name; a card with neither has
    // none. A plain link, as on a Plugins card.
    const q = secretHistoryQuery(s);
    if (q) rule.append(historySearchLink(q, 'Its other sessions', 'secret-sessions-link'));
    if (rule.childNodes.length) card.append(rule);
    list.append(card);
  }
  syncSecretButtons();
  if (story.more) {
    const from = story.secrets.length;
    list.append(restLine(story.more, 'more secret', 'more secrets', all === true, ['secrets'],
      (btn) => showAgentRest(btn, (s) => { s.secrets = true; }, { kind: 'secrets', from })));
  }
  renderRecordedSecrets(story.unchecked === true && Array.isArray(story.recorded) ? story.recorded : []);
  limits.textContent = story.mode === 'off'
    ? 'Protection was off in this session: Mandu only watched and masked nothing.'
    : 'Mandu protects only the secrets you registered and the files you labeled. Anything else the AI read, it saw as it was.' +
      (story.mode === 'secrets' ? ' In this mode Mandu does not stop prompt injection: the AI may follow instructions hidden in what it reads. Mandu guards where your secrets go.' : '');
}

/** What a secret card's *Its other sessions* searches History for
 *  (dashboard.md §4.25b *A card finds its other sessions*): its file as the
 *  card names it (`~/…`, the words History's search finds the card by),
 *  else its key's name (`key`), else nothing. */
function secretHistoryQuery(s) {
  if (typeof s.file === 'string' && s.file) return s.file;
  return typeof s.key === 'string' && s.key ? s.key : '';
}

/** A plain link to History searched for `q` (`data-land` "q:<words>", as a
 *  Plugins card's *Its sessions on History*), named for a screen reader by
 *  what it searches for: "Its other sessions: ~/proj/.env". */
function historySearchLink(q, text, cls) {
  return el('a', { href: routeHref('history') + '?' + historyParams(q, false), 'data-page-link': 'history', 'data-land': 'q:' + q,
    class: cls, text, 'aria-label': text + ': ' + q });
}

/** Where a secret went (dashboard.md §4.25b *Where it went*): the card's
 *  path, one row a fact, each marked by its side of the wall, on your
 *  computer (the real value), at the AI (a placeholder only) or off your
 *  computer (a host Mandu sent the real value to, not set in), an unknown
 *  side read as on your computer; then the line a kept scan gives when the
 *  same secret reached an AI without Mandu, with the Scan page one click
 *  away. Names, paths and times only. */
const PATH_SIDE_WORDS = { computer: 'on your computer', ai: 'at the AI', off: 'off your computer' };
function appendSecretPath(card, s) {
  const path = Array.isArray(s.path) ? s.path : [];
  if (path.length) {
    const heading = el('div', { class: 'secret-path-head', text: 'Where it went' });
    const ol = el('ol', { class: 'secret-path', 'aria-label': 'Where it went' });
    for (const node of path) {
      const side = node.side === 'ai' || node.side === 'off' ? node.side : 'computer';
      ol.append(el('li', { class: 'path-node ' + side + ' ' + (node.tone || 'plain') },
        el('span', { class: 'path-dot', 'aria-hidden': 'true' }),
        el('div', { class: 'path-body' },
          el('div', { class: 'path-caption' }, el('span', { class: 'path-label', text: node.label }), ' ', el('span', { class: 'path-side', text: PATH_SIDE_WORDS[side] })),
          sentenceNode(node.parts, 'path-what'))));
    }
    card.append(heading, ol);
  }
  if (Array.isArray(s.earlier) && s.earlier.length) {
    card.append(el('div', { class: 'secret-earlier', role: 'note' },
      svg(ICON.alert, 14),
      el('div', {}, sentenceNode(s.earlier, ''), ' ',
        scanItemLink(s.scanItem))));
  }
}

/** "See it in Scan": the Scan page at the row of the finding when the card names
 *  it (`?item=`, its fold open at *Where the real value is now*), else the
 *  page. */
function scanItemLink(item) {
  const id = scanItemParam(item);
  return el('a', { href: routeHref('scan') + (id ? '?item=' + id : ''), 'data-page-link': 'scan', ...(id ? { 'data-land': 'item:' + id } : {}), class: 'secret-earlier-link', text: 'See it in Scan' });
}

/** "What this session's record says" (dashboard.md §4.25b *An unchecked
 *  record's path*): under a record Mandu could not check, each secret the
 *  record tells of that no card does, with the path its events draw. No
 *  line, no count and no real value: none of it is a claim Mandu checked,
 *  and the block says so above them. */
function renderRecordedSecrets(recorded) {
  const block = document.getElementById('agent-recorded');
  const list = document.getElementById('agent-recorded-list');
  if (!block || !list) return;
  clear(list);
  block.hidden = !recorded.length;
  for (const s of recorded) {
    const what = el('h3', { class: 'secret-what' }, ...sentenceNode(s.what, '').childNodes);
    const card = el('div', { class: 'secret-card recorded' },
      el('div', { class: 'secret-head' }, what,
        el('span', { class: 'secret-tags' }, el('span', { class: 'tag level', text: s.level }), el('span', { class: 'tag unchecked', text: 'Unchecked record' }))));
    appendSecretPath(card, s);
    if (typeof s.file === 'string' && s.file) {
      card.append(el('div', { class: 'secret-rule' },
        el('a', { href: routeHref('rules', s.file), 'data-page-link': 'rules', 'data-file': s.file, class: 'secret-rule-link',
          text: 'Change it in Rules', 'aria-label': 'Change the rule for ' + s.file + ' in Rules' })));
    }
    list.append(card);
  }
}

/** The files "Files the AI read as they were" lists before its "Show them"
 *  (dashboard.md §4.25b; the server sends up to its READ_AS_IS_CAP). */
const READ_AS_IS_SHOWN = 30;

/** "Files the AI read as they were" under Your secrets (dashboard.md §4.25b):
 *  each file the agent's read tool opened that reached the AI with nothing
 *  masked (the server's `readAsIs`, once a file, first read first), its
 *  first read's time (a link to that step where the story draws it, as a
 *  card's time is) and *Protect it*, a plain link to Rules' Add a rule at
 *  the file (`/rules?file=`), which changes nothing by itself. A fold,
 *  closed on a new visit; a redraw of the same page keeps it as you left
 *  it (`again`). The first READ_AS_IS_SHOWN, then "Show them" for the rest,
 *  which stay shown while the page redraws until the visit ends
 *  (`S.readAsIsAll`); past what the server sends, a count. Paths and times
 *  only. */
function renderReadAsIs(r, again) {
  const fold = document.getElementById('agent-read-as-is');
  const list = document.getElementById('agent-read-as-is-list');
  if (!fold || !list) return;
  clear(list);
  if (!again) fold.open = false;
  const files = r && Array.isArray(r.files) ? r.files : [];
  const more = r && r.more > 0 ? r.more : 0;
  fold.hidden = !files.length;
  if (!files.length) { fold.open = false; return; }
  document.getElementById('agent-read-as-is-title').textContent = 'Files the AI read as they were (' + (files.length + more) + ')';
  const shown = S.readAsIsAll === S.visit ? files : files.slice(0, READ_AS_IS_SHOWN);
  for (const f of shown) {
    const time = el('time', { datetime: f.at, text: hhmm(f.at) || f.at });
    list.append(el('li', { class: 'read-as-is-row' },
      longName(el('code', { class: 'read-as-is-path', text: f.path })),
      el('span', { class: 'read-as-is-at' }, 'read at ', f.step ? stepLink(f.step, time) : time),
      el('a', { href: routeHref('rules', f.path), 'data-page-link': 'rules', 'data-file': f.path, class: 'read-as-is-link',
        text: 'Protect it', 'aria-label': 'Protect ' + f.path + ' in Rules' })));
  }
  const rest = files.length - shown.length;
  if (rest > 0) {
    // The rest, in place: the first of them takes the focus (showRest).
    list.append(showRest(el('li', { class: 'read-as-is-row dim read-as-is-more' }), n(rest, 'more file', 'more files') + '.', [], rest, () => {
      S.readAsIsAll = S.visit;
      renderReadAsIs(r, true);
      const first = list.children[shown.length];
      if (first) landOn(first);
    }));
  } else if (more) {
    list.append(el('li', { class: 'read-as-is-row dim', text: 'and ' + n(more, 'more file', 'more files') + '. Search the steps below for the rest.' }));
  }
}

/** "Changes Mandu did not apply to your files" (dashboard.md §4.25b): the
 *  secret files whose masked copy the agent changed, as the server sent them
 *  (`~/…`, control characters as `?`, at most 20), each breaking at its
 *  slashes, then a count of the rest. Hidden while the session runs, or when
 *  its exit names none. Paths only. */
function renderDiscardedWrites(d) {
  const block = document.getElementById('agent-discarded-block');
  const list = document.getElementById('agent-discarded');
  if (!block || !list) return;
  clear(list);
  const files = d && Array.isArray(d.files) ? d.files.filter((f) => typeof f === 'string' && f) : [];
  block.hidden = !files.length;
  if (!files.length) return;
  for (const f of files) list.append(el('li', { class: 'read-as-is-row' }, longName(el('code', { class: 'read-as-is-path', text: f }))));
  if (d.more > 0) list.append(el('li', { class: 'read-as-is-row dim', text: 'and ' + n(d.more, 'more file', 'more files') + '.' }));
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
    if (shown) row.append(shown.btn, shown.caption);
    if (it.canLetOnce) row.append(el('button', { type: 'button', class: 'btn small prompt-let-once', text: 'Let it through in this message', onclick: () => letPromptThrough(it, 'once', row) }));
    if (it.canLetSession && !onlyThis) row.append(el('button', { type: 'button', class: 'btn small prompt-let-session', text: 'Let it through for this session', onclick: () => letPromptThrough(it, 'session', row) }));
    if (onlyThis) row.append(el('span', { class: 'prompt-let-once-only', text: it.onlyThisMessage }));
    if (lockedWhy) row.append(el('span', { class: 'prompt-let-locked', text: lockedWhy }));
    const ask = letAsk(it, row);
    if (ask) row.append(ask);
    box.append(row);
    if (shown) box.append(shown.pre);
  }
  return box;
}

/** "Show what was hidden": the button, and the text it fills on a click. */
function promptReveal(it, row) {
  const pre = el('pre', { class: 'hidden-text prompt-hidden-text', role: 'group', 'aria-label': 'What was hidden', hidden: true });
  const btn = el('button', { type: 'button', class: 'btn small reveal prompt-reveal', 'aria-expanded': 'false', text: 'Show what was hidden' });
  // When it hides itself again (hideRevealLater); under the button, with it.
  const caption = el('span', { class: 'hidden-caption prompt-hidden-caption', hidden: true });
  const hide = () => {
    pre.hidden = true; caption.hidden = true; clear(pre);
    btn.setAttribute('aria-expanded', 'false');
    btn.textContent = 'Show what was hidden';
  };
  btn.addEventListener('click', async () => {
    if (btn.getAttribute('aria-expanded') === 'true') {
      stopHideLater(btn);
      hide();
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
    pre.hidden = false; caption.hidden = false;
    btn.setAttribute('aria-expanded', 'true');
    btn.textContent = 'Hide it again';
    hideRevealLater(btn, hide, (w) => { caption.textContent = w; });
    focusBack(btn, had, null);
  };
  REVEALS.set(btn, { key: JSON.stringify(['prompt', it.eventId, it.index]), answered });
  return { btn, caption, pre };
}

/** Let it through (in this message, or for this session) asks first, in
 *  the row of the note (letAsk; dashboard.md §4.25y). */
function letPromptThrough(it, scope, row) {
  const key = 'let:' + row.dataset.id;
  dropAsk(key);
  askNow(key, { scope, place: row.contains(document.activeElement) ? true : null }, () => letAsk(it, row), (box) => row.append(box));
}
/** In the row of a masked part of your message, while Let it through asks:
 *  the question it asked in a browser dialog until 2026-10-26, "Let <what>
 *  through in this message? …" (or for the rest of this session), with Let
 *  it through, which sends the answer, and Cancel, which gives the focus
 *  back to the button that asked. Drawn again with the story while the row
 *  still offers that button. */
function letAsk(it, row) {
  const key = 'let:' + row.dataset.id;
  const data = asking(key);
  if (!data) return null;
  const opener = data.scope === 'once' ? '.prompt-let-once' : '.prompt-let-session';
  if (!row.querySelector(opener)) { ASKING = null; return null; }
  const what = it.words || el('code', { text: it.category });
  const words = data.scope === 'once'
    ? ['Let ', what, ' through in this message? The AI reads it as you wrote it from the agent\'s next request on.']
    : ['Let ', what, ' through for the rest of this session? The AI reads it as you wrote it in every message of this session.'];
  const now = () => [...document.querySelectorAll('#agent-story .prompt-note-item')].find((x) => x.dataset.id === row.dataset.id) || row;
  return askBox(key, words, 'Let it through', (box, d) => {
    const at = now();
    // The answer is said on the row, as from its button: the focus goes
    // there first, so a refusal gives it back to the button.
    const had = box.contains(document.activeElement);
    dropAsk(key, d);
    const b = at.querySelector(opener);
    if (had && b) b.focus({ preventScroll: true });
    sendLetThrough(it, d.scope, at);
  }, () => {
    dropAsk(key);
    askOpener(now(), opener);
  }, true);
}
async function sendLetThrough(it, scope, row) {
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
 *  words of an earlier refusal. Also the words of an answer that worked and
 *  leaves its card (keepAnswer), then with `link` after them, if any. */
function letDone(row, text, link) {
  for (const b of row.querySelectorAll('.prompt-let-once, .prompt-let-session, .prompt-let-once-only, .ask-error, .prompt-let-done')) b.remove();
  row.append(el('span', { class: 'prompt-let-done' }, text, link ? ' ' : null, link));
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
  const q = el('div', { class: 'turn-q' }, turnTitle(card, turn.shell ? 'You ran' : turn.prompt ? 'You asked' : 'Before your first question', turn.ts));
  if (turn.shell) {
    q.append(el('div', { class: 'q-text' }, el('code', { text: turn.shell.command })));
    if (turn.shell.output.length) q.append(clipped(turn.shell.output, 'q-out', 'data'));
  } else if (turn.prompt) q.append(clipped(turn.promptParts || [{ kind: 'text', text: turn.prompt }], 'q-text', true));
  if (turn.promptNote) q.append(promptNoteNode(turn.promptNote));
  card.append(el('div', { class: 'turn-head' }, turnTime(turn.ts, turn.id), q));
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
      const more = el('div', { class: 'steps-more' });
      foldFindable(more, true);
      for (const s of run) more.append(stepNode(s));
      const btn = el('button', { type: 'button', class: 'btn small steps-toggle', 'aria-expanded': 'false', text: 'Show ' + n(count, 'more step', 'more steps') });
      btn.addEventListener('click', () => {
        const open = btn.getAttribute('aria-expanded') !== 'true';
        foldFindable(more, !open);
        btn.setAttribute('aria-expanded', String(open));
        btn.textContent = open ? 'Show fewer steps' : 'Show ' + n(count, 'more step', 'more steps');
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
  // answered, the answer of that row, in the words of that page. A standing
  // answer (Always allowed, Allowed for this session, Blocked) ends with
  // Kept in Rules, as that row does (§4.25 *A remembered answer opens where
  // Rules keeps it*).
  if (s.askId) {
    const asked = el('div', { class: 'note asked' }, 'Mandu asked for your OK in ', askRowLink(s.askId, 'Approvals'), '.');
    const answer = answerLabel(s.answer);
    if (answer) asked.append(' Your answer: ' + answer + '.');
    if (s.answer === 'allowed' || s.answer === 'allowed-session' || s.answer === 'blocked') asked.append(' ', keptLink(s.askId));
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
  const ONLY_YOU = 'Only you see this. The AI still has only the masked version. ';
  const caption = el('div', { class: 'hidden-caption', hidden: true, text: ONLY_YOU });
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
  // Hide it again, by the button or by itself (hideRevealLater).
  const hide = () => {
    pre.hidden = true; caption.hidden = true; clear(pre);
    btn.setAttribute('aria-expanded', 'false');
    say(label, !name);
  };
  btn.addEventListener('click', async () => {
    if (btn.getAttribute('aria-expanded') === 'true') {
      stopHideLater(btn);
      hide();
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
    hideRevealLater(btn, hide, (w) => { caption.textContent = ONLY_YOU + w; });
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
/** Each fold's button → its toggle, which a print opens and folds back
 *  without the click's scroll (printOpen). */
const replyToggles = new WeakMap();
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
  replyToggles.set(btn, toggle);
  btn.addEventListener('click', () => {
    const open = btn.getAttribute('aria-expanded') !== 'true';
    toggle(open);
    // Folded again: the button stays in view, under the text it folded
    // (and under the top bar, where it stays in sight).
    if (!open && btn.getBoundingClientRect().top < barRoom() && btn.scrollIntoView) btn.scrollIntoView({ block: 'nearest' });
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

/** Settings › Notifications' "Notify me about", a choice of this browser
 *  (another browser or profile still notifies): 'all' (Everything), 'alarms'
 *  (Only protection problems) or 'none' (Nothing). One key: absent is
 *  Everything, the '1' that Turn off has stored since 2026-10-19 is Nothing,
 *  so nobody who turned them off gets them back, and 'alarms' is Only
 *  protection problems; a value this page does not know reads as Everything,
 *  as any but '1' did. Where storage fails (private mode) it holds for this
 *  tab, as priming does. */
const NOTIFY_OFF_KEY = 'mandu.home.notifyOff';
const NOTIFY_CHOICES = ['all', 'alarms', 'none'];
function notifyChoice() {
  if (S.notifyChoiceTab !== undefined) return S.notifyChoiceTab;
  let v = null;
  try { v = localStorage.getItem(NOTIFY_OFF_KEY); } catch { /* Everything, as before a choice */ }
  return v === '1' ? 'none' : v === 'alarms' ? 'alarms' : 'all';
}
function setNotifyChoice(choice) {
  try {
    if (choice === 'all') localStorage.removeItem(NOTIFY_OFF_KEY);
    else localStorage.setItem(NOTIFY_OFF_KEY, choice === 'none' ? '1' : 'alarms');
    S.notifyChoiceTab = undefined;
  } catch { S.notifyChoiceTab = choice; }
}

/** Home's offer row answered No thanks, in this browser (dashboard.md §4.25
 *  *No thanks on Home's offer*). Its own key, not NOTIFY_OFF_KEY: that is
 *  Settings' choice of what they send, and it leaves the offer alone. Where
 *  storage fails it holds for this tab, as the choice does. */
const NOTIFY_OFFER_KEY = 'mandu.home.notifyOfferHidden';
function notifyOfferHidden() {
  if (S.notifyOfferHiddenTab !== undefined) return S.notifyOfferHiddenTab;
  try { return localStorage.getItem(NOTIFY_OFFER_KEY) === '1'; } catch { return false; }
}
function setNotifyOfferHidden(hidden) {
  try {
    if (hidden) localStorage.setItem(NOTIFY_OFFER_KEY, '1');
    else localStorage.removeItem(NOTIFY_OFFER_KEY);
    S.notifyOfferHiddenTab = undefined;
  } catch { S.notifyOfferHiddenTab = hidden; }
}

/** One notification per ask and per rule change this browser has not seen
 *  (dashboard.md §4.25 *Notifications*). The first visit in a browser
 *  records the backlog silently, so opening the page never floods; after
 *  that, every new one notifies once: asks first, at most three per poll,
 *  and past three one more line, "Mandu: 2 more need your OK". While turned
 *  off in Settings, or set to Only protection problems, nothing is shown,
 *  but every one is still recorded as seen, so turning them on again never
 *  brings the backlog. */
function notifyNewAsks(home) {
  closeAnsweredNotes(home);
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
        fresh.push([askNoteTitle(a), a.sentence.map((p) => p.text).join(''),
          'mandu-ask-' + a.id, () => setPage('approvals', true, undefined, a.id), 'ask', a.id]);
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
      if (title) fresh.push([title, 'Open Approvals to answer it.', 'mandu-proposal-' + p.id, () => setPage('approvals', true, undefined, p.id), 'proposal', p.id]);
    }
  }
  for (const [title, body, tag, open, kind, id] of fresh.slice(0, 3)) {
    keepNote(tag, showAlarm('ask', title, body, tag, open), { kind, id });
  }
  if (fresh.length > 3) {
    // Which kinds it counts, so it closes only on reads of each that answered.
    const kinds = new Set(fresh.slice(3).map((f) => f[4]));
    const was = S.askNotes.get('mandu-more');
    for (const k of (was && was.kinds) || []) kinds.add(k);
    keepNote('mandu-more', showAlarm('ask', 'Mandu: ' + n(fresh.length - 3, 'more needs', 'more need') + ' your OK', 'Open Approvals to see them.',
      'mandu-more', () => setPage('approvals', true)), { kind: 'more', kinds });
  }
}
const PRIMED_KEY = 'mandu.home.notifyPrimed';
/** A question's notification title: the agent and its folder as the card
 *  names them (askedFrom, §4.25u *A question says which session asked*),
 *  "Mandu: Claude Code in ~/projects/shop needs your OK", so two sessions of
 *  one agent tell apart; with no folder known, as before. */
function askNoteTitle(a) {
  if (typeof a.askerCwd === 'string' && a.askerCwd) {
    return 'Mandu: ' + (a.askerAgent || a.agents[0] || 'An agent') + ' in ' + shortPath(a.askerCwd) + ' needs your OK';
  }
  return 'Mandu: ' + (a.agents[0] || 'An agent') + ' needs your OK';
}
/** The question and rule-change notifications this tab showed, by tag
 *  (`mandu-ask-<id>`, `mandu-proposal-<id>`, `mandu-more`), so it can close
 *  them once they no longer wait (closeAnsweredNotes). One that failed to
 *  construct (null) is not kept. */
function keepNote(tag, note, entry) {
  if (note) S.askNotes.set(tag, { ...entry, note });
}
/** Close what this tab showed for a question or rule change that the poll's
 *  answered list no longer holds: answered here or elsewhere, expired, or
 *  decided (dashboard.md §4.25 *A notification closes once nothing waits*).
 *  Only a read that answered judges its kind: a failed one closes nothing.
 *  A question from a session that has ended still waits, so it stays. The
 *  "N more" line closes once every kind it counted answered with none. */
function closeAnsweredNotes(home) {
  const asks = home && home.waitingKnown ? new Set(home.waiting.map((a) => a.id)) : null;
  const proposals = S.proposalsKnown ? new Set(S.proposals.map((p) => p.id)) : null;
  const gone = (kind, id) => {
    const list = kind === 'ask' ? asks : proposals;
    return list !== null && !list.has(id);
  };
  for (const [tag, e] of S.askNotes) {
    const done = e.kind === 'more'
      ? [...e.kinds].every((k) => (k === 'ask' ? asks : proposals) !== null)
        && (asks === null || asks.size === 0) && (proposals === null || proposals.size === 0)
      : gone(e.kind, e.id);
    if (!done) continue;
    S.askNotes.delete(tag);
    try { e.note.close(); } catch { /* already gone */ }
  }
}

/** A new question or rule change, said to a screen reader in the hidden live
 *  region of the top bar, `#top-announce` (dashboard.md §4.25 *A new question is
 *  announced on the page*), whether notifications are on, off or blocked.
 *  The first read that answers records what already waits without a word;
 *  the sets live in page memory, so each tab speaks for itself. A poll that
 *  brings none says nothing and leaves the region as it is; one going away
 *  says nothing. One line per poll at most: one new names its agent, as its
 *  notification does ("Claude Code needs your OK. 2 waiting in
 *  Approvals."), several are counted. Fixed words and the name of the
 *  agent only, never the sentence of a card, secret, file or host. */
function announceNewAsks(home) {
  const lines = [];
  if (home && home.waitingKnown) {
    const met = S.announcedAsks;
    for (const a of home.waiting) {
      if (met && !met.has(a.id)) lines.push((a.agents[0] || 'An agent') + ' needs your OK');
    }
    S.announcedAsks = new Set([...(met || []), ...home.waiting.map((a) => a.id)]);
  }
  // Only a read that answered with a list, as notifyNewAsks; one you asked
  // for yourself is not said (proposalNoteTitle: you know about it).
  if (S.proposalsKnown) {
    const met = S.announcedProposals;
    for (const p of S.proposals) {
      const title = met && !met.has(p.id) ? proposalNoteTitle(p) : null;
      if (title) lines.push(title.replace(/^Mandu: (.)/, (_, c) => c.toUpperCase()));
    }
    S.announcedProposals = new Set([...(met || []), ...S.proposals.map((p) => p.id)]);
  }
  if (!lines.length) return;
  const waiting = (home && home.waitingKnown ? home.waiting.length : 0) + S.proposals.length;
  document.getElementById('top-announce').textContent = lines.length === 1
    ? lines[0] + '. ' + waiting + ' waiting in Approvals.'
    : lines.length + ' new waiting for your OK in Approvals.';
}
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

/** The product's worst states, told to a person not looking at the tab
 *  (dashboard.md §4.25 *Notifications*): a session that newly shows
 *  protection failed, another agent newly able to reach the controls of Mandu,
 *  and the protection service stopping right after a read that listed a
 *  running agent. Called with the answer `loadHome` keeps (`home`), or with
 *  the cause of the poll that failed (`failure`). The words name the agent
 *  only, never a file, host, prompt or secret: a desktop notification can
 *  be mirrored off the machine. */
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
      showAlarm('alarm', 'Mandu: protection failed in ' + (a.agent || 'an agent'),
        'Something reached the AI unmasked. Open its page to see what.',
        'mandu-failed-' + a.id, () => setPage('agent', true, a.id));
    }
    notifyExposure(home.exposure);
    return;
  }
  // Once per stop: the next failed polls follow a failed one, not a read
  // that listed a running agent. A stop between agents says nothing.
  const running = S.alarmRunning === true;
  S.alarmRunning = false;
  if (failure !== 'down' || !running) return;
  showAlarm('alarm', 'Mandu: the protection service stopped',
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
/** Another agent can reach the controls of Mandu (§4.25x): once per
 *  exposure, keyed by when Mandu first saw it (`since`), so two open
 *  tabs show one and a new exposure notifies again. Fixed words: the names
 *  of the causes come from session events, which are claims while it
 *  lasts. A poll with no `since` uses one tag, forgotten when it ends. */
function notifyExposure(x) {
  const seen = readExposureSeen();
  const tag = x ? (Number.isFinite(x.since) ? 'mandu-exposure-' + x.since : 'mandu-exposure') : null;
  const fresh = seen !== null && tag !== null && !seen.has(tag);
  const ids = seen || new Set();
  if (tag) ids.add(tag); else ids.delete('mandu-exposure');
  writeExposureSeen(ids);
  if (!fresh) return;
  showAlarm('alarm', 'Mandu: another agent can reach Mandu\'s controls',
    'Your other agents get masked copies of secret files and masked output until it stops. Open Home to see which agent.',
    tag, () => setPage('home', true));
}
/** The exposures this browser has been told of; null on its first visit,
 *  which records one already showing silently (the asks' priming rule).
 *  Where storage fails (private mode) the tab keeps them. */
const EXPOSURE_KEY = 'mandu.home.seenExposure';
function readExposureSeen() {
  try {
    const v = localStorage.getItem(EXPOSURE_KEY);
    if (v !== null) return new Set(JSON.parse(v));
  } catch { /* the tab's own copy, below */ }
  return S.seenExposureTab ? new Set(S.seenExposureTab) : null;
}
function writeExposureSeen(ids) {
  S.seenExposureTab = [...ids].slice(-50);
  try { localStorage.setItem(EXPOSURE_KEY, JSON.stringify(S.seenExposureTab)); } catch { /* the tab keeps them */ }
}
/** `kind` is 'ask' (a question, a rule change) or 'alarm' (protection
 *  failed, the service stopped, the exposure): Only protection problems
 *  keeps the alarms and silences the rest (dashboard.md §4.25 *Only
 *  protection problems*). */
function showAlarm(kind, title, body, tag, open) {
  const choice = notifyChoice();
  if (choice === 'none' || (choice === 'alarms' && kind !== 'alarm')) return null;
  if (!notifySupported() || Notification.permission !== 'granted') return null;
  return newNote(title, body, tag, open);
}
/** One browser notification; a click focuses the tab and runs `open`. Null
 *  where the constructor throws: Chrome on Android grants the permission but
 *  shows them only from a service worker, and this page has none
 *  (dashboard.md §4.25 *Send a test*). The tab remembers which it was
 *  (`S.notifyBroken`), so Settings › Notifications stops saying "On." for
 *  notifications that can never appear. */
function newNote(title, body, tag, open) {
  let note = null;
  try {
    note = new Notification(title, { body, tag });
    note.onclick = () => { window.focus(); open(); note.close(); };
  } catch { note = null; }
  const broken = note === null;
  if ((S.notifyBroken === true) !== broken) {
    S.notifyBroken = broken;
    S.notifyTest = undefined;
    renderNotifyControls();
  }
  return note;
}

const NOTIFY_CANNOT = 'Use a desktop browser, or keep this tab open: the tab title still counts what waits.';
/** Settings' Send a test: one notification in fixed words, and a line under
 *  the row saying what happened. A browser does not report a notification
 *  that Do Not Disturb or Focus silenced, so "Sent." cannot promise one
 *  appeared. Redraws only its row, so the focus stays on the button. */
function sendTestNotify() {
  const choice = notifyChoice();
  if (!notifySupported() || Notification.permission !== 'granted' || choice === 'none') return;
  const note = newNote('Mandu: notifications work', choice === 'alarms'
    ? 'This is how Mandu tells you when protection fails.'
    : 'This is how Mandu tells you when an agent needs your OK.', 'mandu-test', () => {});
  S.notifyTest = note ? 'sent' : 'broken';
  renderNotifyControls();
}

function renderNotifyControls() {
  const offer = document.getElementById('notify-offer');
  const state = document.getElementById('notify-state');
  const enable = document.getElementById('notify-enable');
  const test = document.getElementById('notify-test');
  const result = document.getElementById('notify-test-result');
  const kindRow = document.getElementById('notify-kind-row');
  const later = document.getElementById('notify-offer-later');
  if (!notifySupported()) {
    offer.hidden = true;
    later.hidden = true;
    kindRow.hidden = true;
    state.textContent = 'This browser cannot show notifications here. They need a secure address (https or localhost).';
    enable.hidden = true;
    test.hidden = true;
    result.hidden = true;
    return;
  }
  const p = Notification.permission;
  // What was drawn from, so a permission the browser changes later redraws
  // (followNotifyPermission).
  S.notifyDrawnPermission = p;
  // Granted: the button turns them off and on in this browser (a page cannot
  // take a permission back), and the menu picks what they are about. The
  // Home offer stays hidden either way.
  const choice = p === 'granted' ? notifyChoice() : 'all';
  const off = choice === 'none';
  offer.hidden = p !== 'default' || notifyOfferHidden();
  // No thanks' line, for this load only, while there is still nothing on.
  later.hidden = !(S.notifyOfferDeclined && p === 'default');
  kindRow.hidden = p !== 'granted';
  document.getElementById('notify-kind').value = choice;
  enable.hidden = p === 'denied';
  // The button keeps what it shows: a press acts on that, not on a
  // permission that changed since (pressNotifyButton).
  enable.dataset.intent = p === 'granted' && !off ? 'off' : 'on';
  enable.textContent = enable.dataset.intent === 'off' ? 'Turn off' : 'Turn on';
  // Send a test only while they send something: the other states say what to do.
  test.hidden = p !== 'granted' || off;
  if (test.hidden) S.notifyTest = undefined;
  result.textContent = S.notifyTest === 'sent'
    ? 'Sent. If nothing appeared, your computer may be set to Do Not Disturb or Focus, or may silence this browser in its notification settings.'
    : S.notifyTest === 'broken' ? 'This browser cannot show Mandu\'s notifications from this page. ' + NOTIFY_CANNOT : '';
  result.hidden = !result.textContent;
  state.textContent = p === 'granted'
    ? (off ? 'Off in this browser. The tab title still counts what waits.'
      : S.notifyBroken ? 'On, but this browser cannot show them from this page. ' + NOTIFY_CANNOT
        : choice === 'alarms'
          ? 'On for protection problems only. You get a notification when protection fails, when the protection service stops under a running agent, and when another agent can reach Mandu\'s controls, while a Mandu tab is open in this browser, also in the background. Not for questions or rule changes: the tab title still counts the questions waiting.'
          : 'On. You get a notification when an agent needs your OK, when protection fails, when the protection service stops under a running agent, and when another agent can reach Mandu\'s controls, while a Mandu tab is open in this browser, also in the background.')
    : p === 'denied'
      ? 'Blocked in this browser. Allow notifications for this site in the browser settings.'
      : 'Off.';
}

async function askNotifyPermission() {
  if (!notifySupported()) return;
  try { await Notification.requestPermission(); } catch { /* old callback-style API: ignore */ }
  // Asking from a button means wanting them, even after an earlier Turn off
  // or No thanks.
  if (Notification.permission === 'granted') {
    setNotifyChoice('all');
    setNotifyOfferHidden(false);
  }
  renderNotifyControls();
}

/** Home's offer, No thanks: hidden in this browser without asking for the
 *  permission, and one line in its place for this load saying where to turn
 *  them on later; the focus moves to that line's link, so it is not lost
 *  with the button. */
function declineNotifyOffer() {
  setNotifyOfferHidden(true);
  S.notifyOfferDeclined = true;
  renderNotifyControls();
  const link = document.getElementById('notify-offer-later-link');
  if (link && !document.getElementById('notify-offer-later').hidden) link.focus();
}

/** Settings' button does what it shows (§4.25 *The button does what it
 *  says*), even when the permission changed under the page since it was
 *  drawn: *Turn off* stores Nothing; *Turn on* stores Everything where the
 *  permission is granted, and otherwise asks for it. Then it redraws only
 *  its own row from the live permission, so the focus stays on it (§4.25 *A
 *  Settings row's button names its row; a change keeps the focus*). */
function pressNotifyButton() {
  if (!notifySupported()) return;
  const intent = document.getElementById('notify-enable').dataset.intent;
  if (intent === 'off') setNotifyChoice('none');
  else if (Notification.permission !== 'granted') { askNotifyPermission(); return; }
  else setNotifyChoice('all');
  renderNotifyControls();
}

/** A permission the browser changes under an open page (another tab's
 *  prompt, the site panel): the row and Home's offer follow it (§4.25 *The
 *  row follows the permission*). Called on the poll and when the tab shows,
 *  also where the permissions `change` event below fires, as some browsers
 *  fire it unevenly; redraws only when it differs from what was drawn. */
function followNotifyPermission() {
  if (notifySupported() && Notification.permission !== S.notifyDrawnPermission) renderNotifyControls();
}
/** The permissions API's `change` event, where the browser has one for
 *  notifications; older Safari has none and some browsers throw or reject,
 *  so the poll above is the fallback. */
function watchNotifyPermission() {
  try {
    const query = navigator.permissions && navigator.permissions.query({ name: 'notifications' });
    if (!query || typeof query.then !== 'function') return;
    query.then((status) => {
      if (status && typeof status.addEventListener === 'function') status.addEventListener('change', followNotifyPermission);
    }, () => { /* no event: the poll follows it */ });
  } catch { /* no event: the poll follows it */ }
}
/** Settings' "Notify me about": stores this browser's choice and redraws
 *  only its row, so the focus stays on the menu. */
function chooseNotifyKind() {
  const v = document.getElementById('notify-kind').value;
  setNotifyChoice(NOTIFY_CHOICES.includes(v) ? v : 'all');
  renderNotifyControls();
}

// ── Settings › Appearance (dashboard.md §4.25 Settings, §4.25k) ──────────────
// Light, dark or the system's, in this browser. The key and values are the
// developer view's Appearance row's, so a pick on either page is the other's
// too (at once in every open product tab, through the `storage` event; in the
// developer view on its next load). 'system' leaves <html> bare, so mandu.css follows
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
  // Another tab's pick (or a storage clear: the system's) is this tab's at
  // once, menu too; the note is this window's own and stays.
  window.addEventListener('storage', (e) => { if (e.key === THEME_KEY || e.key === null) sel.value = applyTheme(lsGet(THEME_KEY)); });
}

/** The tab's shields (dashboard.md §4.25 *The tab says the protection
 *  state*): a pinned tab shows only its icon, so the icon says what the hero
 *  says. Each is the shield of index.html's icon in its colour with one mark;
 *  `on` is that icon itself. `words` lead the tab title. */
const TAB_STATES = {
  on: { fill: '#1e7f4f', mark: "<path d='M11 16l3.5 3.5L21 13' stroke='white' stroke-width='2.5' fill='none' stroke-linecap='round' stroke-linejoin='round'/>" },
  // The hero's shieldOff mark, a cross.
  off: { words: 'Protection off', fill: '#6c6c74', mark: "<path d='M12 11l8 8M20 11l-8 8' stroke='white' stroke-width='2.5' fill='none' stroke-linecap='round'/>" },
  failed: { words: 'Protection failed', fill: '#b4342a', mark: "<path d='M16 9v7.5' stroke='white' stroke-width='2.8' stroke-linecap='round'/><circle cx='16' cy='21.5' r='1.8' fill='white'/>" },
  'not-connected': { words: 'Not connected', fill: '#6c6c74', mark: '' },
};
/** The state the tab says, from the hero's verdict: a failed poll is not
 *  connected; no read yet, or a verdict this page does not know (an older
 *  server), says nothing (null), and the tab keeps its baseline. */
function tabState() {
  if (!S.home) return S.homeFailure ? 'not-connected' : null;
  const v = S.home.verdict;
  if (v === 'off' || v === 'failed') return v;
  if (v === 'unknown') return 'not-connected';
  return v === 'protected' || v === 'quiet' || v === 'secrets-only' || v === 'waiting' ? 'on' : null;
}
/** "(3) Protection off · Mandu" in the tab, the count first, and the state's
 *  shield as its icon, with the count on it. */
function renderTitle() {
  const k = (S.home && S.home.waitingKnown ? S.home.waiting.length : 0) + S.proposals.length;
  const state = tabState();
  const said = state ? TAB_STATES[state].words : null;
  document.title = (k ? '(' + k + ') ' : '') + (said ? said + ' · ' : '') + (S.pageTitle || 'Mandu');
  const link = document.getElementById('favicon');
  if (!link) return;
  if (!S.baseFavicon) S.baseFavicon = link.href;
  const shield = state || 'on';
  const label = !k ? '' : k > 9 ? '9+' : String(k);
  // The top bar's grey (§4.25 *The top bar's two marks*): no agent is held
  // up by what is counted, so the dot is not the amber.
  const ended = nothingHeldUp(S.home, k);
  // Written only when what it shows changed, as the rest of the poll.
  if (sameAsDrawn('tab-icon', [shield, label, ended])) return;
  if (shield === 'on' && !label) { link.href = S.baseFavicon; return; }
  const { fill, mark } = TAB_STATES[shield];
  // The count's dot takes the mark's place, which it would cover at 16 px.
  // The grey one is the Off shield's grey (white digit 5.2:1), so a white
  // ring tells it from that shield.
  const dot = ended ? "fill='#6c6c74' stroke='white' stroke-width='1.5'" : "fill='#a35d00'";
  const svgText = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    + "<path d='M16 3l10 4v8c0 7-5 11-10 14C11 26 6 22 6 15V7z' fill='" + fill + "'/>"
    + (label
      ? "<circle cx='23' cy='9' r='9' " + dot + "/>"
        + "<text x='23' y='13' font-size='" + (label.length > 1 ? 9 : 12) + "' font-family='sans-serif' font-weight='700' fill='white' text-anchor='middle'>" + label + '</text>'
      : mark)
    + '</svg>';
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
  M.unread.shown = causeKey(M.unread.cause);
  host.append(el('div', { class: 'empty' }, ...cannotCheck(lead, M.unread.cause, true, 'the model list shows here')));
}

// Settings: each card is read when the page opens, after each change made
// in it (readsInOrder: never a row drawn as it was before a later change),
// and when it changed elsewhere (followSettings).
const MODEL_READS = readsInOrder();
const LABEL_READS = readsInOrder();
const PROMPT_READS = readsInOrder();

/** Settings follows a change made elsewhere (dashboard.md §4.25 *Settings
 *  follows a change made elsewhere*), as Rules does (RULES_SEEN): Models,
 *  Sensitivity labels and Prompt filters are sections of policy.yaml, so a
 *  change to any of them moves `rulesVersion` of /api/home. Per card:
 *  `version`, the one its drawn read is at least as new as; `after`, the
 *  Home poll (a count of S.homeAsked) a read the page asked itself was asked
 *  at: that read forgets the version, and the first poll asked after it
 *  gives it, silently, so a change the page made is never said to come from
 *  elsewhere; `was`, the version before a follow read, kept again if that
 *  read fails; `drawn`, a digest of what the card drew (settingsDraws). Per
 *  card, so a label saved here does not hide a model changed meanwhile. */
const SETTINGS_SEEN = {
  models: { version: null, after: 0, was: null, drawn: null },
  labels: { version: null, after: 0, was: null, drawn: null },
  prompt: { version: null, after: 0, was: null, drawn: null },
};
/** A read of a Settings card is asked: `opts.follow`, the version a follow
 *  read follows (followSettings); else a read the page asked itself, which
 *  forgets the version and takes the card's line away. */
function settingsAsked(card, opts) {
  const seen = SETTINGS_SEEN[card];
  if (typeof opts.follow === 'string') { seen.was = seen.version; seen.version = opts.follow; return; }
  seen.version = null;
  seen.after = S.homeAsked;
  settingsChangedLine(card, false);
}
/** A read of a Settings card answered: whether it draws. `digest`: what it
 *  would draw (Models: its list, your administrator's part and the
 *  networks, never the rest of policy/panel, whose approvals queue an
 *  answer given in Approvals changes; Labels and Prompt filters: their own
 *  view model), null when it could not be read. A read the page asked
 *  draws. A follow read draws only content that changed, and says so;
 *  one that could not be read draws nothing and keeps the version before
 *  it, so a later poll follows again; one a read the page asked since
 *  outdates draws nothing (that read draws). */
function settingsDraws(card, opts, digest) {
  const seen = SETTINGS_SEEN[card];
  if (typeof opts.follow !== 'string') { seen.drawn = digest; return true; }
  if (seen.version !== opts.follow) return false;
  if (digest === null) { seen.version = seen.was; return false; }
  if (digest === seen.drawn) return false;
  seen.drawn = digest;
  settingsChangedLine(card, true);
  return true;
}
const SETTINGS_CHANGED_WORDS = {
  models: 'Your models changed since this page was read. It shows them now.',
  labels: 'Your sensitivity labels changed since this page was read. It shows them now.',
  prompt: 'Your prompt filters changed since this page was read. It shows them now.',
};
/** The card's own line, above its notice (never in it: the notice keeps
 *  the page's own last change and its Undo). */
function settingsChangedLine(card, show) {
  const line = document.getElementById(card + '-changed');
  if (!line) return;
  line.hidden = !show;
  line.textContent = show ? SETTINGS_CHANGED_WORDS[card] : '';
}

/** On each Home poll that answered (`asked`, its number) while Settings is
 *  shown in a visible tab: each card whose version differs from
 *  `rulesVersion` is read again (a follow read), unless it is under the
 *  person's hands, then by the first poll after it settles. A card that
 *  could not be read is left to readAgainUnread. The place and the focus
 *  are kept as the poll keeps them. A server with no `rulesVersion`:
 *  nothing. */
function followSettings(asked) {
  const v = S.home && S.home.rulesVersion;
  if (S.page !== 'settings' || tabHidden() || typeof v !== 'string') return;
  const cards = [
    ['models', () => !!M.unread, modelsUnderHands, loadModels],
    ['labels', () => S.unread.has('labels'), labelsUnderHands, loadLabels],
    ['prompt', () => S.unread.has('prompt'), () => promptUnderHands() || settingsBusy('settings-prompt-block'), loadPromptSettings],
  ];
  for (const [card, unread, held, load] of cards) {
    const seen = SETTINGS_SEEN[card];
    if (asked <= seen.after || seen.version === v) continue;
    if (seen.version === null) { seen.version = v; continue; }
    if (unread() || held()) continue;
    const place = pollPlace(document.getElementById('main'));
    load({ follow: v }).then(() => { if (place && S.page === 'settings') pollRefocus(place); });
  }
}
/** A change of the card is on its way: its row's buttons and menus are off
 *  (busyRow), or its notice's Undo. */
function settingsBusy(id) {
  const card = document.getElementById(id);
  return !!card && !!card.querySelector('button:disabled, select:disabled');
}
function settingsFocusIn(id) {
  const card = document.getElementById(id);
  return !!card && card.contains(document.activeElement);
}
function settingsAsking(prefix) { return !!ASKING && String(ASKING.key).startsWith(prefix); }
/** Settings › Models is in use: the focus in the card, the form open, a
 *  model's question open or a change on its way. */
function modelsUnderHands() {
  const form = modelField('model-form');
  return settingsFocusIn('settings-models-block') || (!!form && !form.hidden) || settingsAsking('model') || settingsBusy('settings-models-block');
}
/** The level each label's picker was drawn with (labelLevelPicker). */
const PICK_DRAWN = new WeakMap();
/** Settings › Sensitivity labels is in use: the focus in the card, a level
 *  picked that is not the one drawn ("Not saved"), a name typed for a
 *  label with no level, a label's question open or a change on its way. */
function labelsUnderHands() {
  if (settingsFocusIn('settings-labels-block') || settingsAsking('label:') || settingsBusy('settings-labels-block')) return true;
  const host = document.getElementById('settings-labels');
  if (!host) return false;
  if ([...host.querySelectorAll('.label-name')].some((x) => x.value.trim() !== '')) return true;
  return [...host.querySelectorAll('select.label-level')].some((x) => PICK_DRAWN.has(x) && x.value !== PICK_DRAWN.get(x));
}

/** `opts.follow`: a follow read (followSettings), which draws only a list
 *  that changed (settingsDraws). */
async function loadModels(opts = {}) {
  const host = document.getElementById('settings-models');
  if (!host) return;
  const asked = MODEL_READS.ask();
  settingsAsked('models', opts);
  let panel = null;
  let failure = null;
  try { panel = (await apiGet('policy/panel')).panel; } catch (err) { panel = null; failure = readFailure(err); }
  if (!MODEL_READS.take(asked)) return;
  // A list that could not be read offers no Add: there is nothing to add to
  // (dashboard.md §4.25 "Empty states").
  const unread = !panel || !Array.isArray(panel.models);
  if (!settingsDraws('models', opts, unread ? null : JSON.stringify([panel.models, panel.modelsAdmin || null, panel.perimeter || null]))) return;
  clear(host);
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
    for (const m of panel.models) host.append(modelRow(m), ...withAsk(modelAsk(m.name)));
  }
  // Plan 12 D5: your administrator's models you removed, with a way back.
  for (const r of (admin && admin.removed) || []) host.append(removedAdminRow(r), ...withAsk(modelAsk(r.name)));
}
/** A question's box to draw after its row: none while none asks. */
function withAsk(box) { return box ? [box] : []; }

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
    noticeChangeLink(box, 'Models', changeId);
  }
}

function modelField(id) { return document.getElementById(id); }

function openModelForm(m) {
  const form = modelField('model-form');
  dropAsk('modelform');
  form.reset();
  modelField('model-error').textContent = '';
  markModelFields([]);
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
  dropAsk('modelform');
  form.reset();
  markModelFields([]);
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

/** What the person is asked before a change in Settings applies (Models,
 *  Sensitivity labels, Prompt filters; dashboard.md §4.25n), from the
 *  server's answer `d`: the change, its rows as sentences (`words`, the
 *  box's sentence), then under it (`more`) "This changes what Mandu
 *  protects:" with what it would let as a list, and each warning as its own
 *  line. Names are codes, never markup. Until 2026-10-26 the same rows were
 *  one plain text for window.confirm (modelConfirmText), ending "Continue?":
 *  the box's buttons say that now. */
function confirmParts(d) {
  const words = [];
  for (const r of d.rows || []) {
    if (words.length) words.push(' ');
    for (const p of r) words.push(partNode(p, nameCode, (text) => document.createTextNode(text)));
    words.push('.');
  }
  if (!words.length) words.push('This change makes protection weaker.');
  const more = [];
  if ((d.wouldLet || []).length) more.push(el('div', { class: 'ask-in-place-k', text: 'This changes what Mandu protects:' }), rowList(d.wouldLet, 'ask-in-place-list'));
  for (const w of d.warnings || []) {
    const warn = sentenceNode(w, 'proposal-warn');
    warn.setAttribute('role', 'note');
    warn.prepend('Warning: ');
    more.push(warn);
  }
  return { words, more };
}
/** The box of a Settings question (`key`), drawn from the server's rows
 *  (confirmParts): `yes` its button's words. */
function settingsAskBox(key, yes, onYes, back) {
  const data = asking(key);
  if (!data) return null;
  const { words, more } = confirmParts(data.d);
  return askBox(key, words, yes, onYes, back, true, more);
}

/** Send one change to the model list. The server answers a change that
 *  loosens protection with `confirm: true` and the rows to ask with; the
 *  same change sent again with its `expected` (`asked`: the question
 *  answered) applies. */
function sendModelChange(body, asked) {
  return apiPost('policy/models/change', asked ? { ...body, expected: asked.expected } : body);
}

function modelError(r) {
  const d = r && r.data;
  if (d && Array.isArray(d.problems) && d.problems.length) return (d.error || 'Not saved.') + ' ' + d.problems.join('; ');
  return refusalText(r, 'could not save the model (' + (r ? r.status : 'no answer') + ')');
}

/** A refused Save of the Models form speaks the form's words (dashboard.md
 *  §4.25l *A refusal speaks the form's words*). The validator writes each
 *  problem against a policy.yaml key (`url: …`, `token_env: …`) the page
 *  never shows: a line that starts with a key the form edits is drawn with
 *  that field's label and marks the field, the two key phrases are reworded,
 *  and any other line is drawn as the service wrote it. For the form only:
 *  modelError's other callers keep the service's words. */
const MODEL_FORM_KEYS = [
  ['name', 'model-name', 'Name'],
  ['url', 'model-url', 'Address'],
  ['wire', 'model-wire', 'API style'],
  ['model', 'model-model', 'Model'],
  ['token_env', 'model-token-env', 'Token variable name'],
  ['local', 'model-local', 'This is my own model'],
  ['helper', 'model-helper', 'Read my own-model files with this one'],
  ['allow_plain_http', 'model-plain-http', 'Send without encryption'],
];
const MODEL_FORM_PHRASES = [
  ['add allow_plain_http: true to accept that', 'tick Send without encryption to accept that'],
  ['remove local: true', 'untick This is my own model'],
];
function modelFormRefusal(r) {
  const d = r && r.data;
  if (!(d && Array.isArray(d.problems) && d.problems.length)) return { text: modelError(r), fields: [] };
  const fields = [];
  const lines = d.problems.map((p) => {
    let line = String(p);
    const key = MODEL_FORM_KEYS.find(([k]) => line.startsWith(k + ': '));
    if (key) {
      line = key[2] + ': ' + line.slice(key[0].length + 2);
      if (!fields.includes(key[1])) fields.push(key[1]);
    }
    for (const [said, words] of MODEL_FORM_PHRASES) line = line.split(said).join(words);
    return line;
  });
  return { text: (d.error || 'Not saved.') + ' ' + lines.join('; '), fields };
}
/** The two patterns the validator applies word for word (policy-file-
 *  validate.ts MODEL_NAME_RE, ENV_NAME_RE; a stack test pins them), checked
 *  before Save sends: a miss is answered at once, in the form's words. The
 *  service still judges every Save. An empty Name is left to the field's
 *  `required` and the service. */
const MODEL_NAME_FORM = /^[A-Za-z0-9_.-]{1,64}$/;
const TOKEN_ENV_FORM = /^[A-Za-z_][A-Za-z0-9_]*$/;
function modelFormMisses(model) {
  const lines = [];
  const fields = [];
  if (model.name !== '' && !MODEL_NAME_FORM.test(model.name)) {
    lines.push('Name: use 1 to 64 letters, digits, _ . or - (no spaces).');
    fields.push('model-name');
  }
  if (model.tokenEnv !== '' && !TOKEN_ENV_FORM.test(model.tokenEnv)) {
    lines.push('Token variable name: use the variable\'s name alone, such as OLLAMA_API_KEY: letters, digits and _, not starting with a digit (no $ or spaces).');
    fields.push('model-token-env');
  }
  return lines.length ? { text: 'Not saved. ' + lines.join(' '), fields } : null;
}
/** Mark the fields a refusal names (`ids`), and only those. */
function markModelFields(ids) {
  for (const f of modelField('model-form').querySelectorAll('[aria-invalid]')) f.removeAttribute('aria-invalid');
  for (const id of ids) modelField(id).setAttribute('aria-invalid', 'true');
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
  // A field changed while the form asks: the question was about other
  // values, so it goes, and Save asks again.
  // A field a refusal marked is unmarked once it is edited.
  for (const type of ['input', 'change']) {
    form.addEventListener(type, (e) => {
      if (e.target.closest('.ask-in-place')) return;
      dropAsk('modelform');
      e.target.removeAttribute('aria-invalid');
    });
  }
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    // Save pressed, or Enter in a field: the focus is in the form.
    const had = modelFormHad();
    const err = modelField('model-error');
    err.textContent = '';
    markModelFields([]);
    dropAsk('modelform');
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
    // Refused before sending: nothing goes, and the focus stays where the
    // press left it (Save, or the field Enter was pressed in), as after a
    // refusal by the service.
    const miss = modelFormMisses(model);
    if (miss) { setWords(err, miss.text); markModelFields(miss.fields); return; }
    save.disabled = true;
    const body = original ? { action: 'update', name: original, model, version: M.formVersion } : { action: 'add', model };
    const r = await sendModelChange(body);
    save.disabled = false;
    if (r.ok && r.data && r.data.confirm) {
      askNow('modelform', { body, expected: r.data.expected, d: r.data, place: had ? true : null }, modelFormAsk,
        (box) => form.querySelector('.form-actions').before(box));
      return;
    }
    await modelFormAnswered(r, body, had);
  });
}

/** The Models form's question (dashboard.md §4.25n), above its buttons:
 *  Save anyway sends the change asked about with its `expected`; Cancel
 *  and Escape keep the form open, as typed, and give the focus back to
 *  Save. The box takes its Escape, so the form's own (Cancel) does not
 *  close the form with it. */
function modelFormAsk() {
  const save = modelField('model-save');
  return settingsAskBox('modelform', 'Save anyway', async (box, d) => {
    const had = modelFormHad();
    d.busy = true;
    busyRow(box, true);
    save.disabled = true;
    const r = await sendModelChange(d.body, d);
    save.disabled = false;
    d.busy = false;
    dropAsk('modelform', d);
    await modelFormAnswered(r, d.body, had);
  }, () => {
    dropAsk('modelform');
    if (reachable(save)) save.focus();
  });
}

/** The form's change answered (`body`, as sent; `had`: the focus was in the
 *  form at the press): refused, the form stays with the words why; saved,
 *  it closes, the notice says so with its Undo, and the list is read again. */
async function modelFormAnswered(r, body, had) {
  const err = modelField('model-error');
  const save = modelField('model-save');
  const original = body.action === 'update' ? body.name : '';
  const model = body.model;
  if (r.status === 409 && r.data && r.data.stale) {
    // The model changed somewhere else while the form was open: nothing
    // was saved. The list is read again and the form keeps what was
    // typed; its next Save names the model as it is now.
    setWords(err, modelError(r));
    if (modelFormFell(had)) save.focus();
    await modelFormReread(original, err);
    return;
  }
  if (!r.ok || !r.data || !r.data.applied) {
    const refused = modelFormRefusal(r);
    setWords(err, refused.text);
    markModelFields(refused.fields);
    if (modelFormFell(had)) save.focus();
    return;
  }
  closeModelForm();
  MODEL_READS.wrote();
  // Taken before the list is drawn again, which drops a focus put on one
  // of its rows meanwhile: that one was moved by the person.
  const back = modelFormFell(had);
  modelsNotice((original ? 'Saved ' : 'Added ') + model.name + '. ' + (r.data.note || ''), r.data.changeId);
  await loadModels();
  if (back && modelFormFell(had)) modelFormBack(original ? model.name : null);
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

/** Remove on a model's row, or Bring back on your administrator's model
 *  you removed (`action`: remove | restore). A change that loosens
 *  protection asks under the row (modelAsk) and is sent again with its
 *  `expected` by Remove anyway or Restore anyway (`asked`: that question). */
async function modelRowChange(name, action, row, asked) {
  const key = 'model:' + name;
  const place = asked ? asked.place : settingsPlace(row);
  if (!asked) dropAsk(key);
  busyRow(row, true);
  if (asked) asked.busy = true;
  const r = await sendModelChange({ action, name }, asked);
  if (!asked && r.ok && r.data && r.data.confirm) {
    busyRow(row, false);
    askNow(key, { action, expected: r.data.expected, d: r.data, place }, () => modelAsk(name), (box) => row.after(box));
    return;
  }
  if (asked) {
    asked.busy = false;
    dropAsk(key, asked);
    row = modelRowAt(name) || row;
  }
  if (!r.ok || !r.data || !r.data.applied) { busyRow(row, false); showAskError(row, modelError(r)); settingsRefocus(place, row); return; }
  MODEL_READS.wrote();
  modelsNotice((action === 'remove' ? 'Removed ' : 'Brought back ') + name + '. ' + (r.data.note || ''), r.data.changeId);
  await loadModels();
  settingsRefocus(place);
}
function removeModel(m, row) { return modelRowChange(m.name, 'remove', row, null); }
function restoreModel(r, row) { return modelRowChange(r.name, 'restore', row, null); }
/** The row of the model `name` drawn now in Settings › Models. */
function modelRowAt(name) {
  return [...document.querySelectorAll('#settings-models .model-row')].find((x) => x.dataset.name === name) || null;
}
/** Under a model's row, the question its Remove or Bring back asks
 *  (dashboard.md §4.25n), drawn again with the list; Cancel gives the
 *  focus back to the button. */
function modelAsk(name) {
  const key = 'model:' + name;
  const data = asking(key);
  if (!data) return null;
  const opener = data.action === 'remove' ? '.model-remove-btn' : '.model-restore-btn';
  return settingsAskBox(key, data.action === 'remove' ? 'Remove anyway' : 'Restore anyway',
    (box, d) => modelRowChange(name, d.action, box, d),
    () => { dropAsk(key); askOpener(modelRowAt(name), opener); });
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
/** The words of unread sensitivity labels: the refusal in the words of the
 *  page, and while the latest Home poll says Mandu is not running at all,
 *  that (dashboard.md §4.25 *Protection is off when nothing runs*). */
function labelsUnreadWords(r) {
  if (notRunningNow() && noService(r)) return notRunningWords('your sensitivity labels show here');
  return refusalText(r, 'The sensitivity labels could not be read.');
}
/** Draw the unread line again with the words it says now
 *  (followCannotCheck). */
function drawLabelsUnread() {
  const u = S.labelsUnread;
  u.shown = labelsUnreadWords(u.r);
  setWords(u.line, u.shown);
}
/** The labels Office put on documents, and the level each is suggested at.
 *  The server lists the levels you chose (and your administrator's, read
 *  only) and the labels the last scan found with no level yet; Save sends
 *  one change, asked about first when it lowers what Mandu suggests. */
async function loadLabels(opts = {}) {
  const host = document.getElementById('settings-labels');
  if (!host) return;
  const asked = LABEL_READS.ask();
  settingsAsked('labels', opts);
  const r = await apiGetControl('policy/sensitivity-labels').catch(() => null);
  if (!LABEL_READS.take(asked)) return;
  const vm = r && r.ok && r.data && r.data.labels;
  const unread = !vm || !Array.isArray(vm.mappings) || !Array.isArray(vm.unmapped);
  if (!settingsDraws('labels', opts, unread ? null : JSON.stringify(vm))) return;
  clear(host);
  S.labelsUnread = null;
  if (unread) {
    S.unread.add('labels');
    S.labelsUnread = { line: el('div', { class: 'empty' }), r, shown: null };
    host.append(S.labelsUnread.line);
    drawLabelsUnread();
    return;
  }
  S.unread.delete('labels');
  for (const m of vm.mappings) host.append(...labelWithAsk(labelMappingRow(m, vm)));
  for (const u of vm.unmapped) host.append(...labelWithAsk(labelUnmappedRow(u, vm)));
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
  PICK_DRAWN.set(sel, sel.value);
  return sel;
}

/** A label that has a level: its name, its id, the level, and Save / Remove
 *  (read only when your administrator set it). Save waits for a change
 *  (syncLabelSave). */
function labelMappingRow(m, vm) {
  const row = el('div', { class: 'row service label-row', 'data-id': m.id, 'data-site': m.site || '' });
  if (!m.admin) row.setAttribute('data-level', m.level);
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
  acts.append(el('button', { type: 'button', class: 'btn small label-save-btn', text: 'Save', 'aria-label': 'Save the level for ' + (m.name || m.id), onclick: () => {
    if (pick.value === m.level) return;
    sendLabelChange({ action: 'map', id: m.id, ...(m.site ? { site: m.site } : {}), name: m.name, level: pick.value, version: m.version }, row, 'Saved ' + (m.name || m.id) + '.');
  } }));
  acts.append(el('button', { type: 'button', class: 'btn small label-remove-btn', text: 'Remove', 'aria-label': 'Remove the level for ' + (m.name || m.id), onclick: () =>
    sendLabelChange({ action: 'unmap', id: m.id, ...(m.site ? { site: m.site } : {}), version: m.version }, row, 'Removed ' + (m.name || m.id) + '.') }));
  row.append(acts);
  pick.addEventListener('change', () => syncLabelSave(row));
  syncLabelSave(row);
  return row;
}

/** Save waits for a change (dashboard.md §4.25s *Save waits for a change*):
 *  on a label that has a level, Save is greyed while the picker shows the
 *  level saved, and a press then sends nothing; a level picked that differs
 *  lights it and says so under the row, "Not saved: press Save to use Any
 *  AI, when it asks.". `aria-disabled`, not `disabled`, which would drop the
 *  focus Save is given back after a save (pollRefocus) to the heading. A
 *  row with no level yet (no `data-level`) always sends a change. */
function syncLabelSave(row) {
  const saved = row.getAttribute('data-level');
  const pick = row.querySelector('.label-level');
  const save = row.querySelector('.label-save-btn');
  if (saved === null || !pick || !save) return;
  const changed = pick.value !== saved;
  if (changed) save.removeAttribute('aria-disabled');
  else save.setAttribute('aria-disabled', 'true');
  let line = row.querySelector('.label-unsaved');
  if (!changed) { if (line) line.remove(); return; }
  if (!line) { line = el('div', { class: 'field-hint label-unsaved' }); row.querySelector('.model-actions').after(line); }
  const words = pick.selectedOptions[0] ? pick.selectedOptions[0].textContent : pick.value;
  setWords(line, 'Not saved: press Save to use ' + words + '.');
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
    noticeChangeLink(box, 'Sensitivity labels', changeId);
  }
}

/** One change: asked about first, under the row, when the server says it
 *  lowers what Mandu suggests (the same question as Settings › Models,
 *  labelAsk), and sent again with its `expected` by Save anyway or Remove
 *  anyway (`asked`: that question). It names the mapping's version as the
 *  row was read (dashboard.md §4.25s *A change names the label as it was
 *  read*). */
async function sendLabelChange(body, row, done, asked) {
  const key = asked ? asked.key : labelAskKey(row);
  const place = asked ? asked.place : settingsPlace(row);
  if (!asked) dropAsk(key);
  busyRow(row, true);
  if (asked) asked.busy = true;
  const r = await apiPost('policy/sensitivity-labels/change', asked ? { ...body, expected: asked.expected } : body);
  if (!asked && r.ok && r.data && r.data.confirm) {
    busyRow(row, false);
    askNow(key, { key, body, done, expected: r.data.expected, d: r.data, place }, () => labelAsk(key), (box) => row.after(box));
    return;
  }
  if (asked) {
    asked.busy = false;
    dropAsk(key, asked);
    row = labelRowAt(key) || row;
  }
  if (r.status === 409 && r.data && r.data.stale) { await labelStaleReread(row, r, place); return; }
  if (!r.ok || !r.data || !r.data.applied) { busyRow(row, false); showAskError(row, modelError(r)); settingsRefocus(place, row); return; }
  LABEL_READS.wrote();
  labelsNotice(done + ' ' + (r.data.note || ''), r.data.changeId);
  await loadLabels();
  settingsRefocus(place);
}

/** The question of a label's row is keyed by the row (its organization and
 *  id), as settingsPlace finds it. */
function labelAskKey(row) {
  return 'label:' + JSON.stringify([row.getAttribute('data-site') || '', row.getAttribute('data-id')]);
}
function labelRowAt(key) {
  return [...document.querySelectorAll('#settings-labels .label-row')].find((x) => labelAskKey(x) === key) || null;
}
/** Under a label's row, the question its Save or Remove asks (dashboard.md
 *  §4.25n): Save anyway or Remove anyway sends the change asked about;
 *  Cancel keeps the row as you left it and gives the focus back to the
 *  button. */
function labelAsk(key) {
  const data = asking(key);
  if (!data) return null;
  const remove = data.body.action === 'unmap';
  return settingsAskBox(key, remove ? 'Remove anyway' : 'Save anyway',
    (box, d) => sendLabelChange(d.body, box, d.done, d),
    () => { dropAsk(key); askOpener(labelRowAt(key), remove ? '.label-remove-btn' : '.label-save-btn'); });
}
/** A label's row and, while it asks, its question under it: the level
 *  picked and the name typed for the change asked about are put back on a
 *  row drawn again. */
function labelWithAsk(row) {
  const key = labelAskKey(row);
  const box = labelAsk(key);
  if (!box) return [row];
  const body = asking(key).body;
  const pick = row.querySelector('.label-level');
  if (pick && body.level && [...pick.options].some((o) => o.value === body.level)) pick.value = body.level;
  const name = row.querySelector('.label-name');
  if (name && typeof body.name === 'string') name.value = body.name;
  syncLabelSave(row);
  return [row, box];
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
  syncLabelSave(again);
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
  // Mandu not running at all (§4.25 *Protection is off when nothing runs*):
  // that, never "not connected".
  if (notRunningNow() && noService(u.r)) return notRunningWords('your prompt filter settings show here');
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
async function loadPromptSettings(opts = {}) {
  const host = document.getElementById('settings-prompt-kinds');
  if (!host) return;
  const exHost = document.getElementById('settings-prompt-exceptions');
  const meanings = document.getElementById('settings-prompt-meanings');
  const form = document.getElementById('prompt-exception-form');
  const asked = PROMPT_READS.ask();
  settingsAsked('prompt', opts);
  // This read says what runs as of the last Home poll, or later: a restart
  // after it is followed (followRunningAnswers), the one before it is not
  // read twice.
  const running = secretsRunning(S.home);
  if (running !== null) S.runningFollowed.settings = running;
  const r = await apiGetControl('policy/prompt-filters').catch(() => null);
  if (!PROMPT_READS.take(asked)) return;
  const vm = r && r.ok && r.data && r.data.settings;
  const unread = !vm || !vm.available || !Array.isArray(vm.kinds);
  if (!settingsDraws('prompt', opts, unread ? null : JSON.stringify(vm))) return;
  clear(host); clear(exHost); clear(meanings);
  if (unread) S.unread.add('prompt'); else S.unread.delete('prompt');
  // Unread, the block is its refusal alone: no meanings, and no Exceptions
  // heading over a list that cannot be read (dashboard.md §4.25 "Empty states").
  // The meanings go with their fold: a "What the choices mean" that opens
  // on nothing is hidden too, as when a server sends no meanings.
  const noMeanings = unread || !(vm.meanings || []).length;
  for (const id of ['settings-prompt-meanings-fold', 'settings-prompt-meanings', 'settings-prompt-exceptions-head', 'settings-prompt-exceptions-about', 'settings-prompt-exceptions', 'settings-prompt-try']) {
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
  for (const k of vm.kinds) host.append(...promptWithAsk(promptKindRow(k)));
  for (const m of vm.meanings || []) meanings.append(el('dt', { text: m.words }), el('dd', { text: m.meaning }));
  const kind = document.getElementById('prompt-exception-kind');
  // A follow read keeps the kind chosen for the next exception, when it is
  // still offered (any other read starts the form over, as before).
  const chosen = typeof opts.follow === 'string' ? kind.value : '';
  clear(kind);
  for (const k of vm.exceptionKinds || []) kind.append(el('option', { value: k.category, text: k.name }));
  if (chosen && [...kind.options].some((o) => o.value === chosen)) kind.value = chosen;
  // The form asking keeps the kind it asks about.
  const formAsk = asking('promptform');
  if (formAsk && [...kind.options].some((o) => o.value === formAsk.edit.category)) kind.value = formAsk.edit.category;
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
  for (const x of vm.exceptions) exHost.append(...promptWithAsk(promptExceptionRow(x)));
  S.promptExceptionsInForce = vm.exceptions.filter((x) => x.inForce).length;
  // Try a message's answer follows what was just read (§4.25y *The answer
  // follows the card*).
  promptTryAgain();
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
  deliberateMenu(sel, row, 'prompt:' + k.category, sel.value, () => {
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
    noticeChangeLink(box, 'Prompt filters', changeId);
  }
}

/** One change: asked about first when the server says it lets more reach
 *  the AI (the same question as Settings › Models), under the row or in
 *  the exception form above its button (promptAsk), and sent again with
 *  its `expected` by Apply anyway (`asked`: that question). A refusal, such
 *  as a kind your administrator locked, is said on the row. True once
 *  applied. */
async function sendPromptChange(edit, row, done, asked) {
  const key = asked ? asked.key : promptAskKey(row);
  const place = asked ? asked.place : settingsPlace(row);
  if (!asked) dropAsk(key);
  busyRow(row, true);
  if (asked) asked.busy = true;
  const r = await apiPost('policy/prompt-filters/change', asked ? { edit, expected: asked.expected } : { edit });
  if (!asked && r.ok && r.data && r.data.confirm) {
    busyRow(row, false);
    const opener = key === 'promptform' ? '#prompt-exception-add' : edit.op === 'remove-prompt-action' ? '.prompt-reset-btn'
      : edit.op === 'remove-prompt-exception' ? '.prompt-exception-remove' : '.prompt-action';
    askNow(key, { key, edit, done, opener, expected: r.data.expected, d: r.data, place }, () => promptAsk(key),
      (box) => (key === 'promptform' ? row.querySelector('.form-actions').before(box) : row.after(box)));
    return false;
  }
  if (asked) {
    asked.busy = false;
    dropAsk(key, asked);
    row = promptRowAt(key) || row;
  }
  if (!r.ok || !r.data || !r.data.applied) { busyRow(row, false); showAskError(row, modelError(r)); settingsRefocus(place, row); return false; }
  PROMPT_READS.wrote();
  promptNotice(done + ' It applies to your next message.', r.data.changeId);
  await loadPromptSettings();
  settingsRefocus(place);
  return true;
}

/** The question of a prompt filter change is keyed by its place: a kind's
 *  row, an exception's row, or the exception form. */
function promptAskKey(row) {
  if (row.id === 'prompt-exception-form') return 'promptform';
  const match = row.getAttribute('data-match');
  return 'prompt:' + JSON.stringify(match === null ? ['kind', row.getAttribute('data-category')] : ['exception', row.getAttribute('data-category'), match]);
}
function promptRowAt(key) {
  if (key === 'promptform') return document.getElementById('prompt-exception-form');
  return [...document.querySelectorAll('#settings-prompt-kinds .prompt-kind, #settings-prompt-exceptions .prompt-exception')].find((x) => promptAskKey(x) === key) || null;
}
/** A prompt filter change's question (dashboard.md §4.25n): Apply anyway
 *  sends the change asked about. Cancel gives the focus back to what asked
 *  (the kind's menu, Use the default, Remove, Add exception); on a row the
 *  list is read again, so a kind's menu shows the choice in force again,
 *  while the exception form keeps what was typed. */
function promptAsk(key) {
  const data = asking(key);
  if (!data) return null;
  return settingsAskBox(key, 'Apply anyway', async (box, d) => {
    const ok = await sendPromptChange(d.edit, box, d.done, d);
    if (ok && key === 'promptform') document.getElementById('prompt-exception-match').value = '';
  }, () => {
    dropAsk(key);
    askOpener(promptRowAt(key), data.opener);
    if (key === 'promptform') return;
    loadPromptSettings().then(() => { if (focusFell()) askOpener(promptRowAt(key), data.opener); });
  });
}
/** A kind's or an exception's row and, while it asks, its question under
 *  it; a kind's menu drawn again shows the choice asked about. */
function promptWithAsk(row) {
  const key = promptAskKey(row);
  const box = promptAsk(key);
  if (!box) return [row];
  const edit = asking(key).edit;
  const sel = row.querySelector('.prompt-action');
  if (sel && edit.op === 'set-prompt-action' && [...sel.options].some((o) => o.value === edit.action)) sel.value = edit.action;
  return [row, box];
}

function wirePromptExceptionForm() {
  const form = document.getElementById('prompt-exception-form');
  if (!form) return;
  // What it asks about changed while the form asks: the question goes.
  for (const type of ['input', 'change']) {
    form.addEventListener(type, (e) => { if (!e.target.closest('.ask-in-place')) dropAsk('promptform'); });
  }
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

// ── Settings › Prompt filters › Try a message (dashboard.md §4.25y) ─────────
/** What would happen to a finding of each action, as the end of its line. */
const PROMPT_TRY_OUTCOME = {
  mask: 'hidden. The AI would get a short code in its place.',
  redact: 'removed. The AI would read a note in its place.',
  ask: 'held. The message would wait for your answer.',
  block: 'blocked. The message would not be sent.',
  log: 'sent as written. Mandu would only note it.',
  pass: 'sent as written.',
};
/** The latest try, a press or a re-ask: an answer to an older one is dropped. */
let promptTrySeq = 0;
/** The text the drawn answer is about, as it was tried (the box may have
 *  been edited since); null while no answer is drawn. Page memory only:
 *  the fold says nothing is kept. */
let promptTried = null;
/** The press of Try it still out (its seq), or 0; and whether a change
 *  came while it was, so the card is asked again once it answers. */
let promptTryPress = 0;
let promptTryAgainAfter = false;

/** The answer to a try, drawn under the box: the typed text with each
 *  found span marked, one line per finding (its kind in the card's words,
 *  what would happen to it), or why nothing is marked. Everything from the
 *  server is drawn as text; the answer holds no text the AI would get. */
function drawPromptTry(box, text, d) {
  clear(box);
  box.hidden = false;
  const found = (Array.isArray(d.findings) ? d.findings : [])
    .filter((f) => Number.isInteger(f.start) && Number.isInteger(f.end) && f.start >= 0 && f.end > f.start && f.end <= text.length)
    .sort((a, b) => a.start - b.start);
  if (!found.length) {
    box.append(el('p', { class: 'prompt-try-none', text: d.reason || 'Nothing in it would be held or masked.' }));
  } else {
    const said = el('p', { class: 'prompt-try-said' });
    const lines = el('ul', { class: 'prompt-try-lines' });
    let at = 0;
    for (const f of found) {
      if (f.start < at) continue; // overlapping: the first one is marked
      if (f.start > at) said.append(text.slice(at, f.start));
      said.append(el('mark', { class: 'prompt-try-mark', 'data-category': String(f.category || ''), text: text.slice(f.start, f.end) }));
      at = f.end;
      const outcome = Object.prototype.hasOwnProperty.call(PROMPT_TRY_OUTCOME, f.action) ? PROMPT_TRY_OUTCOME[f.action] : String(f.action || '') + '.';
      lines.append(el('li', { class: 'prompt-try-line' }, promptKindName({ name: String(f.name || f.category || ''), named: f.named === true }), ': ' + outcome));
    }
    if (at < text.length) said.append(text.slice(at));
    box.append(said, lines);
    if (d.enforcing === false) box.append(el('p', { class: 'prompt-try-off', text: 'Protection is off, so Mandu would only note these.' }));
  }
  if (S.promptExceptionsInForce > 0) {
    box.append(el('p', { class: 'prompt-try-except', text: 'What matches one of your exceptions is not marked: it goes to the AI as you wrote it.' }));
  }
}

/** The fold's form: one dry run of the filter on the typed text (POST
 *  /api/policy/prompt-filters/try). Nothing is sent to an AI and nothing
 *  is kept; the text stays in the box. */
function wirePromptTry() {
  const form = document.getElementById('prompt-try-form');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = document.getElementById('prompt-try-text');
    const err = document.getElementById('prompt-try-error');
    const box = document.getElementById('prompt-try-answer');
    const go = document.getElementById('prompt-try-go');
    err.textContent = '';
    const text = input.value;
    if (!text.trim()) { clear(box); box.hidden = true; promptTried = null; err.textContent = 'Type a message to try.'; return; }
    const mine = ++promptTrySeq;
    promptTryPress = mine;
    go.disabled = true;
    form.setAttribute('aria-busy', 'true');
    let r = null;
    try { r = await apiPost('policy/prompt-filters/try', { text }); } catch { r = null; }
    if (mine !== promptTrySeq) return;
    promptTryPress = 0;
    go.disabled = false;
    form.removeAttribute('aria-busy');
    const again = promptTryAgainAfter;
    promptTryAgainAfter = false;
    if (!r || !r.ok || !r.data) {
      clear(box); box.hidden = true; promptTried = null;
      setWords(err, refusalText(r, 'Mandu could not try this message.'));
      return;
    }
    drawPromptTry(box, text, r.data);
    promptTried = text;
    // A change made while it was out may postdate the answer: ask again.
    if (again) promptTryAgain();
  });
  // Ctrl+Enter (Cmd+Enter on a Mac) presses Try it, as in Rules › Describe;
  // Enter alone still makes a new line.
  document.getElementById('prompt-try-text').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' || !(e.ctrlKey || e.metaKey) || e.altKey || e.isComposing) return;
    e.preventDefault();
    document.getElementById('prompt-try-go').click();
  });
}

/** After a read of the card (a change made on it, its Undo, Settings opened
 *  again): the drawn answer is asked again for the text it is about and
 *  drawn in place, with no busy button and no focus move. Nothing drawn,
 *  nothing asked. A press still out asks again once it answers. A re-ask
 *  that fails keeps the answer and says it is from before the change, never
 *  a refusal the person did not ask for (dashboard.md §4.25y *The answer
 *  follows the card*). */
async function promptTryAgain() {
  if (promptTryPress) { promptTryAgainAfter = true; return; }
  const box = document.getElementById('prompt-try-answer');
  const text = promptTried;
  if (text === null || !box || box.hidden) return;
  const mine = ++promptTrySeq;
  let r = null;
  try { r = await apiPost('policy/prompt-filters/try', { text }); } catch { r = null; }
  if (mine !== promptTrySeq) return;
  if (r && r.ok && r.data) { drawPromptTry(box, text, r.data); return; }
  if (!box.querySelector('.prompt-try-stale')) {
    box.append(el('p', { class: 'prompt-try-stale', text: 'This answer is from before your last change. Press Try it to check again.' }));
  }
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

/** The service line says only "Stopped." (and Start) while Mandu is not
 *  running: the Protection sentence above already says it, and how it
 *  starts (dashboard.md §4.25 *Protection is off when nothing runs*, *Said
 *  once*). Any other state, or stopped while Mandu runs, keeps its sentence. */
function serviceQuiet(sum) {
  return !!sum && sum.available === true && sum.state === 'stopped' && notRunningNow();
}
/** The Home poll: the line follows `notRunning` (serviceQuiet), drawn again
 *  from the summary it was drawn from, never while a request of its own is
 *  out or Restart's question is open (followServices holds the same). */
function followServiceQuiet() {
  if (!S.services || S.serviceOut > 0 || document.getElementById('settings-service-confirm')) return;
  const sum = JSON.parse(S.services);
  if (serviceQuiet(sum) !== S.serviceQuiet) drawServices(sum);
}

function drawServices(sum) {
  const host = document.getElementById('settings-services');
  clear(host);
  S.serviceQuiet = serviceQuiet(sum);
  // Restart's question sits under the row, outside the line: it goes with it.
  const asked = document.getElementById('settings-service-confirm');
  if (asked) asked.remove();
  S.services = sum ? JSON.stringify(sum) : null;
  S.serviceState = sum && sum.available ? sum.state : null;
  const dot = document.querySelector('#settings-protect-row .name .dot');
  if (dot) dot.className = 'dot ' + protectDot();
  if (!sum) {
    host.append(el('span', { class: 'service-none' }, 'This dashboard was started without the service controls. Start it with ',
      runCode('mandu dashboard'), ' to manage the protection service here.'));
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
    // A sentence that names a command has its parts (the adopted one:
    // `mandu stop` as code).
    const parts = S.serviceQuiet ? null : Array.isArray(sum.sentenceParts) && sum.sentenceParts.length ? sum.sentenceParts : null;
    const sentence = S.serviceQuiet ? '' : sum.sentence;
    const line = el('div', { id: 'settings-service-main' }, el('span', { class: 'service-state', text: sum.name }), '.',
      parts ? ' ' : null, parts ? textParts(parts, sentence) : sentence ? ' ' + sentence : null,
      since ? ' Started ' : null, since, since ? '.' : null);
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
/** The commands index.html names for you to run (`code[data-run]`, the
 *  dashboard account's `mandu dashboard --set-password`, Where your data
 *  lives' `mandu paths`, About's `mandu doctor`): each gets the
 *  Copy runCode draws, once, at boot. */
function wireRunCodes() {
  if (!canCopy()) return;
  for (const c of document.querySelectorAll('code[data-run]')) {
    const box = el('span', { class: 'run-code' });
    c.replaceWith(box);
    box.append(c, ...copyButton(c.textContent, 'Copy ' + c.textContent, 'run-copy'));
  }
}
/** `/` finds (dashboard.md §4.25 *`/` finds*): each page's Find box, by
 *  id, in the order taken; Approvals' *Find a change* when *Find an
 *  answer* is hidden. */
const SLASH_FIND = { history: ['history-q'], approvals: ['answered-q', 'changes-q'], rules: ['rules-find'] };
/** The page's Find box `/` goes to: shown (neither it nor a block around
 *  it `hidden`, as #55 and #141 hide them) and enabled; none elsewhere. */
function slashFindBox() {
  for (const id of SLASH_FIND[S.page] || []) {
    const box = document.getElementById(id);
    if (box && !box.disabled && !box.closest('[hidden]')) return box;
  }
  return null;
}
/** A plain `/` outside any text box, menu or editable text puts the cursor
 *  in the page's Find box with its text selected, and only then keeps the
 *  `/` from the box and the browser; otherwise the browser keeps its own
 *  `/` (Firefox's quick find). */
function slashFinds(e) {
  if (e.key !== '/' || e.ctrlKey || e.altKey || e.metaKey || e.isComposing || e.defaultPrevented) return;
  const t = e.target;
  if (t instanceof Element && t.closest('input, textarea, select, [contenteditable]:not([contenteditable="false"])')) return;
  const box = slashFindBox();
  if (!box) return;
  e.preventDefault();
  box.focus();
  box.select();
}
function boot() {
  document.addEventListener('keydown', slashFinds);
  wireStaticHelp();
  wireRunCodes();
  wireNav();
  drawSectionLinks();
  wireHistorySearch();
  wireAnsweredSearch();
  wireChangesSearch();
  document.getElementById('agent-only').addEventListener('click', flipAgentOnly);
  document.getElementById('agent-latest').addEventListener('click', goToLatestTurn);
  document.getElementById('agent-story').addEventListener('beforematch', findOpens);
  window.addEventListener('beforeprint', printOpen);
  window.addEventListener('afterprint', printClose);
  wireLockForm();
  wireRuleFind();
  wireModelForm();
  wirePromptExceptionForm();
  wirePromptTry();
  wireDescribe();
  renderNotifyControls();
  wireAppearance();
  document.getElementById('notify-offer-btn').addEventListener('click', askNotifyPermission);
  document.getElementById('notify-offer-no').addEventListener('click', declineNotifyOffer);
  document.getElementById('home-scan-fold').addEventListener('click', () => foldScanCard(true));
  document.getElementById('home-scan-show').addEventListener('click', () => foldScanCard(false));
  // No thanks' link: Settings at its Notifications card, as a section link
  // goes; a modifier click is the browser's.
  const offerLater = document.getElementById('notify-offer-later-link');
  offerLater.href = routeHref('settings') + '#notifications';
  offerLater.addEventListener('click', (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button > 0) return;
    e.preventDefault();
    goToSection('settings', 'notifications', 'settings-notify-block');
  });
  document.getElementById('notify-enable').addEventListener('click', pressNotifyButton);
  document.getElementById('notify-test').addEventListener('click', sendTestNotify);
  document.getElementById('notify-kind').addEventListener('change', chooseNotifyKind);
  // Another tab's Turn off / Turn on, or No thanks on Home: this tab's row
  // and offer say so too.
  window.addEventListener('storage', (e) => { if (e.key === NOTIFY_OFF_KEY || e.key === NOTIFY_OFFER_KEY || e.key === null) renderNotifyControls(); });
  // A permission the browser changes: the row and offer follow it.
  watchNotifyPermission();
  // Another tab's choices on Rules, and the suggestions it skipped.
  window.addEventListener('storage', syncFromOtherTab);
  const dataWhere = document.getElementById('home-data');
  dataWhere.addEventListener('toggle', () => { if (dataWhere.open) loadDataLocations(); });
  const route = currentRoute();
  const load = setPage(route.page, false, route.session, route.ask);
  // The first read of Home draws Rules' Built-in protections and part of
  // Settings: a card the address names waits for it too.
  const homeRead = loadHome();
  landAtSection(Promise.all([load, homeRead]));
  // The poll, every POLL_MS and at once on a return to the tab: Home, also
  // while the tab is hidden, so a background tab notifies and its title and
  // icon count what waits (dashboard.md §4.25 *A background tab keeps
  // reading*); on Settings the service row (followServices) only while shown.
  const shown = () => document.visibilityState === 'visible';
  setInterval(() => { followNotifyPermission(); if (shown() || tabHidden()) loadHome(); if (shown()) followServices(); }, POLL_MS);
  document.addEventListener('visibilitychange', () => { if (shown()) { followNotifyPermission(); loadHome(); followServices(); } });
}
boot();
