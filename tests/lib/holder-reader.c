/*
 * mdu-holder: a raw holder the sandbox and live tests build and pin by path
 * and hash (tests/lib/holder-reader.ts, launcher/test/*-live.test.sh).
 *
 *   mdu-holder FILE...           writes each FILE's bytes to stdout (as cat)
 *   mdu-holder -o DST FILE...    writes them to DST instead, mode 0644 (a copy)
 *
 * Purpose-built rather than a renamed copy of GNU cat or cp: since the !437
 * leftover (2) (2026-10-03, plan 13 D8) a binary byte-identical to a printer
 * on the host admits nothing under any name. It is a printer by behaviour,
 * on purpose: the tests' subject is what happens to a secret once a process
 * the human named holds it, and a binary the human pins is theirs to vouch
 * for (plan 13 §4.9).
 */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int copy(int in, int out) {
  char buf[65536];
  for (;;) {
    ssize_t n = read(in, buf, sizeof buf);
    if (n == 0) return 0;
    if (n < 0) return 1;
    for (ssize_t off = 0; off < n;) {
      ssize_t w = write(out, buf + off, (size_t)(n - off));
      if (w < 0) return 1;
      off += w;
    }
  }
}

int main(int argc, char **argv) {
  int first = 1, out = 1;
  if (argc > 2 && strcmp(argv[1], "-o") == 0) {
    out = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { perror(argv[2]); return 1; }
    first = 3;
  }
  if (first >= argc) {
    fprintf(stderr, "usage: %s [-o DST] FILE...\n", argv[0]);
    return 2;
  }
  int rc = 0;
  for (int i = first; i < argc; i++) {
    int in = open(argv[i], O_RDONLY);
    if (in < 0) { perror(argv[i]); rc = 1; continue; }
    if (copy(in, out) != 0) { perror(argv[i]); rc = 1; }
    close(in);
  }
  if (out != 1 && close(out) != 0) { perror("mdu-holder"); return 1; }
  return rc;
}
