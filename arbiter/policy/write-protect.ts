/**
 * write-protect — the labels of the launcher's write-protect list
 * (sandbox-security-review-2026-09-28 finding 6). Mandu-new.
 *
 * The guard holds a change to a file that runs later outside Mandu and asks
 * the arbiter (`decideProtectedWrite`), passing the entry's label for the
 * Inbox sentence. The request arrives on the data socket, which the agent's
 * tree can reach, so the arbiter shows a label only when it is one of these,
 * the words the launcher itself writes (launcher/src/write-protect.ts; the
 * two lists are pinned equal by
 * tests/stack/write-protect-labels-parity.test.ts).
 */
export const PROTECTED_WRITE_LABELS: ReadonlySet<string> = new Set([
  "a shell startup file",
  "a systemd user unit",
  "a desktop autostart entry",
  "a user environment file",
  "an ssh setting",
  "a git setting",
  "a git hook",
  "an OpenCode plugin or tool",
  "an OpenCode setting",
  // policy.yaml write_protect: deny / ask (guard-settings.ts).
  "a file you protected in policy.yaml",
]);
