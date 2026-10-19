/*
 * scripts/lib/subreaper.c — an entry's subreaper (docs/design/testing/
 * test-organization.md §8.5, "Strays"). run-suites.mjs compiles it once per
 * run with the host's `cc` (libc only) and starts every entry under it:
 *
 *   mdu-subreaper <cmd...>
 *
 * It marks itself a child subreaper (PR_SET_CHILD_SUBREAPER), so every
 * orphan of the entry's tree is reparented to it, not to init; the runner
 * finds them as its children once the entry's group is gone. It reaps every
 * child that ends, as init would (a test that waits for an orphan to be gone
 * sees it gone), and reports on fd 3:
 *
 *   "pid <n> <start ticks>"   the entry started (its session and group are <n>);
 *                             its start read before anything can reap it
 *   "exit <code> <signal>"    it ended ("-" for none)
 *   "error <message>"         it could not start
 *
 * and ends when its stdin (from the runner) reaches end of file: the runner
 * is done with the strays, or died.
 *
 * Why C: node cannot call prctl(2) nor reap a child it did not spawn, and an
 * interpreter above the entry is one of its ancestors: a guard that trusts a
 * `from: python3` parent looks at every ancestor, and a python3 subreaper made
 * launcher/test/secret-readers-live.test.sh's refusals pass (the first
 * pipeline of !1667); a node one that never reaped left orphans as zombies,
 * alive to `kill -0` (guard-death-live).
 *
 * The entry runs as the runner ran it before: a new session, stdin
 * /dev/null, stdout and stderr this process's (the entry's log), no other
 * descriptor, default signal dispositions, the environment as given.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static void say(const char *line) {
  size_t n = strlen(line);
  while (n > 0) {
    ssize_t w = write(3, line, n);
    if (w < 0 && errno == EINTR) continue;
    if (w <= 0) return;
    line += w;
    n -= (size_t)w;
  }
}

static const char *errname(int e) {
  switch (e) {
    case ENOENT: return "ENOENT";
    case EACCES: return "EACCES";
    case ENOEXEC: return "ENOEXEC";
    case ENOTDIR: return "ENOTDIR";
    case E2BIG: return "E2BIG";
    case ENOMEM: return "ENOMEM";
    case EAGAIN: return "EAGAIN";
    default: return NULL;
  }
}

static const char *signame(int s) {
  static const char *names[] = {
    NULL, "SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP", "SIGABRT", "SIGBUS", "SIGFPE",
    "SIGKILL", "SIGUSR1", "SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM", "SIGSTKFLT",
    "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP", "SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU",
    "SIGXFSZ", "SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO", "SIGPWR", "SIGSYS",
  };
  if (s > 0 && s < (int)(sizeof names / sizeof names[0])) return names[s];
  return NULL;
}

/* Field 22 of /proc/<pid>/stat (its start, in clock ticks since boot). */
static int start_ticks(pid_t pid, char *out, size_t cap) {
  char path[64], buf[2048];
  snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t n = read(fd, buf, sizeof buf - 1);
  close(fd);
  if (n <= 0) return -1;
  buf[n] = 0;
  char *p = strrchr(buf, ')');
  if (!p) return -1;
  p += 2; /* the state */
  for (int field = 3; field < 22; field++) {
    p = strchr(p, ' ');
    if (!p) return -1;
    p++;
  }
  size_t len = strcspn(p, " ");
  if (len == 0 || len >= cap) return -1;
  memcpy(out, p, len);
  out[len] = 0;
  return 0;
}

int main(int argc, char **argv) {
  char line[512];
  if (argc < 2) {
    say("error usage: mdu-subreaper <cmd...>\n");
    return 2;
  }
  if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
    snprintf(line, sizeof line, "error PR_SET_CHILD_SUBREAPER: %s\n", strerror(errno));
    say(line);
    return 1;
  }
  /* The child tells a failed exec by this pipe (closed by a good one). */
  int ep[2];
  if (pipe2(ep, O_CLOEXEC) != 0) {
    snprintf(line, sizeof line, "error pipe: %s\n", strerror(errno));
    say(line);
    return 1;
  }
  pid_t child = fork();
  if (child < 0) {
    snprintf(line, sizeof line, "error fork: %s\n", strerror(errno));
    say(line);
    return 1;
  }
  if (child == 0) {
    setsid();
    int null = open("/dev/null", O_RDONLY);
    if (null >= 0 && null != 0) {
      dup2(null, 0);
      close(null);
    }
    /* Nothing of ours but stdio and the exec-error pipe crosses the exec. */
    for (int fd = 3; fd < 1024; fd++)
      if (fd != ep[1]) close(fd);
    execvp(argv[1], argv + 1);
    int e = errno;
    ssize_t w = write(ep[1], &e, sizeof e);
    (void)w;
    _exit(127);
  }
  close(ep[1]);
  int e = 0;
  ssize_t got;
  do got = read(ep[0], &e, sizeof e); while (got < 0 && errno == EINTR);
  close(ep[0]);
  if (got == (ssize_t)sizeof e) {
    const char *name = errname(e);
    waitpid(child, NULL, 0);
    if (name) snprintf(line, sizeof line, "error spawn %s %s\n", argv[1], name);
    else snprintf(line, sizeof line, "error spawn %s errno %d\n", argv[1], e);
    say(line);
    return 1;
  }
  char ticks[32];
  if (start_ticks(child, ticks, sizeof ticks) != 0) strcpy(ticks, "-");
  snprintf(line, sizeof line, "pid %d %s\n", (int)child, ticks);
  say(line);
  int entry_done = 0;
  for (;;) {
    int st;
    pid_t p;
    while ((p = waitpid(-1, &st, WNOHANG)) > 0) {
      if (p == child && !entry_done) {
        entry_done = 1;
        if (WIFEXITED(st)) {
          snprintf(line, sizeof line, "exit %d -\n", WEXITSTATUS(st));
        } else if (WIFSIGNALED(st)) {
          const char *s = signame(WTERMSIG(st));
          if (s) snprintf(line, sizeof line, "exit - %s\n", s);
          else snprintf(line, sizeof line, "exit - SIG%d\n", WTERMSIG(st));
        } else {
          snprintf(line, sizeof line, "exit - -\n");
        }
        say(line);
      }
    }
    struct pollfd pf = {.fd = 0, .events = POLLIN};
    int rc = poll(&pf, 1, 50);
    if (rc > 0) {
      char b[256];
      ssize_t n = read(0, b, sizeof b);
      if (n == 0 || (n < 0 && errno != EINTR && errno != EAGAIN)) return 0;
    }
  }
}
