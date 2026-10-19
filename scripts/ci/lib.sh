# scripts/ci/lib.sh — host-side helpers shared by vm-image.sh and vm-run.sh
# (docs/design/testing/continuous-integration.md §4, §8). Sourced, not run.
#
#   ci_image_key <rev>|--worktree [guest]  the image key (16 hex chars)
#   ci_image_name <guest> <key>            the image's name (mandu-ci-…)
#   ci_check_guest / ci_pins_prefix / ci_image_glob   the guests (§4.1)
#   ci_key_files <rev>|--worktree          the "path blob-id" lines it hashes
#   ci_source_tar <rev>|--worktree <out>   a tar of the tree under src/
#   ci_append_baselines <store> <out> [max]  the promoted replay baselines into it
#   ci_append_costs <runs> <out> [last]    the entries' measured costs into it
#   ci_render_job_env                      job.env from the CI_JOB_* variables
#   ci_guest_budget <timeout>              the guest's budget (MANDU_CI_BUDGET, §3)
#   ci_read_pins <pins.env>                load KEY=value lines as variables
#   ci_accel                               qemu acceleration args (KVM or none)
#
# The caller sets CI_REPO_ROOT (the checkout, a git work tree).

# Mandu's own locations come from the path table (docs/design/architecture/on-disk-layout.md §5).
# shellcheck source=scripts/paths/mandu-paths.sh
. "$(dirname "${BASH_SOURCE[0]}")/../paths/mandu-paths.sh"
# guest_register / guest_release: every qemu guest vm-run.sh and vm-image.sh
# start is registered for `mandu reap` (os-test-matrix.md §10.5).
# shellcheck source=scripts/lib/guest-registry.sh
. "$(dirname "${BASH_SOURCE[0]}")/../lib/guest-registry.sh"

# The files whose content decides the image (§4): the pins, the image builder,
# the guest's own files, every lockfile outside node_modules (private/ ones
# too, when the checkout has them: the source repo runs its private rows), and
# the cargo lockfile. Anything else is source, which a run brings itself.
# Filters "path<TAB>…" lines on their path.
ci_key_filter() {
  grep -E $'^(scripts/ci/pins\\.env|scripts/ci/vm-image\\.sh|scripts/ci/guest/[^\t]+|interceptors/Cargo\\.lock|([^\t]+/)?package-lock\\.json)\t' \
    | grep -Ev '^([^\t]*/)?node_modules/' | LC_ALL=C sort
}

# ci_key_files <rev>|--worktree — one "path<TAB>blob-id" line per key file,
# sorted. The blob id is git's content hash, so a work tree whose key files
# equal the commit's yields the same lines as the commit.
ci_key_files() {
  local src="$1"
  if [[ "$src" == --worktree ]]; then
    local p
    git -C "$CI_REPO_ROOT" ls-files -co --exclude-standard | sed 's/$/\t/' | ci_key_filter \
      | while IFS=$'\t' read -r p _; do
          [[ -f "$CI_REPO_ROOT/$p" ]] || continue
          printf '%s\t%s\n' "$p" "$(git -C "$CI_REPO_ROOT" hash-object -- "$p")"
        done
  else
    git -C "$CI_REPO_ROOT" rev-parse --verify --quiet "$src^{commit}" >/dev/null \
      || { echo "ci_key_files: not a commit: $src" >&2; return 1; }
    git -C "$CI_REPO_ROOT" ls-tree -r --full-tree "$src" \
      | awk -F'\t' '{ split($1, m, " "); if (m[2] == "blob") print $2 "\t" m[3] }' \
      | ci_key_filter
  fi
}

# The guests an image can be built from (continuous-integration.md §4.1). The
# default, ubuntu-2404, is every per-push run's; ubuntu-2604 (Linux 7.0) runs
# the kernel lane on the newer kernel (the `kernel-linux-7` job). Each has its
# own base-image pins in pins.env (ci_pins_prefix) and its own images.
CI_GUESTS="ubuntu-2404 ubuntu-2604"
CI_DEFAULT_GUEST=ubuntu-2404

# ci_check_guest <name> — 0 for a known guest; else a message and 1.
ci_check_guest() {
  [[ " $CI_GUESTS " == *" $1 "* && -n "$1" ]] && return 0
  echo "ci: unknown guest '$1' (known: $CI_GUESTS)" >&2
  return 1
}

# ci_pins_prefix <guest> — the prefix of the guest's base-image pins in
# pins.env: <prefix>CLOUD_BASE, <prefix>CLOUD_RELEASE, <prefix>CLOUD_IMAGE.
ci_pins_prefix() {
  case "$1" in
    ubuntu-2404) echo UBUNTU_ ;;
    ubuntu-2604) echo UBUNTU_2604_ ;;
    *) ci_check_guest "$1"; return 1 ;;
  esac
}

# ci_image_name <guest> <key> — the image's name (no .qcow2): mandu-ci-<key>
# for the default guest (the names every image had before there were two), and
# mandu-ci-<guest>-<key> for another, so the cache, the logs and a run's
# summary (its `image`) say which guest ran.
ci_image_name() {
  if [[ "$1" == "$CI_DEFAULT_GUEST" ]]; then echo "mandu-ci-$2"; else echo "mandu-ci-$1-$2"; fi
}

# ci_image_glob <guest> — the cache's images of that guest (vm-image.sh prunes
# each guest's images on their own). A key is hex, so it never starts with the
# `u` of a guest name.
ci_image_glob() {
  if [[ "$1" == "$CI_DEFAULT_GUEST" ]]; then echo "mandu-ci-[0-9a-f]*.qcow2"; else echo "mandu-ci-$1-*.qcow2"; fi
}

# ci_image_key <rev>|--worktree [guest] — the key. Another guest than the
# default hashes its name too, so the two guests never share a key; the
# default's key is what it was before there were two.
ci_image_key() {
  local lines guest="${2:-$CI_DEFAULT_GUEST}"
  ci_check_guest "$guest" || return 1
  lines="$(ci_key_files "$1")" || return 1
  { echo "mandu-ci-image-key-v1"
    [[ "$guest" == "$CI_DEFAULT_GUEST" ]] || echo "guest $guest"
    printf '%s\n' "$lines"; } | sha256sum | cut -c1-16
}

# ci_append_baselines <store> <out.tar> [max-bytes] — the host's promoted
# replay baselines (the path table's `drill-baselines`: <key>/baseline.json,
# what collect-results.mjs promoted from passing master runs) appended to the
# input tar under src/.mandu-ci/baselines/, newest first up to max-bytes
# (default 512 MiB), so a per-push run `use`s them and runs only the Mandu
# side (test-reorganization.md §6.9, step 5 decision 8). Only a regular file
# named baseline.json directly under a directory named like a key goes in.
# Prints how many went in; 0 when the store is absent or empty.
CI_BASELINE_KEY_RE='^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$'
ci_append_baselines() {
  local store="$1" out="$2" max="${3:-$((512 * 1024 * 1024))}" list n=0 total=0 f key size
  [[ -d "$store" && ! -L "$store" ]] || { echo 0; return 0; }
  list="$(mktemp)" || return 1
  while IFS= read -r f; do
    key="${f%/baseline.json}"; key="${key##*/}"
    [[ "$key" =~ $CI_BASELINE_KEY_RE && "$key" != *..* ]] || continue
    [[ -f "$store/$key/baseline.json" && ! -L "$store/$key/baseline.json" && ! -L "$store/$key" ]] || continue
    size="$(stat -c %s "$store/$key/baseline.json")" || continue
    (( total + size > max )) && continue
    total=$((total + size)); n=$((n + 1))
    printf '%s/baseline.json\n' "$key" >> "$list"
  done < <(find "$store" -mindepth 2 -maxdepth 2 -name baseline.json -type f -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-)
  if (( n > 0 )); then
    tar -rf "$out" -C "$store" --transform 's,^,src/.mandu-ci/baselines/,' --owner=0 --group=0 --numeric-owner -T "$list" \
      || { rm -f "$list"; return 1; }
  fi
  rm -f "$list"
  echo "$n"
}

# ci_append_costs <runs dir> <out.tar> [last] — the entries' measured costs
# (continuous-integration.md §5.4): each entry's median duration over this
# host's last <last> (default 10) green full runs in <runs dir> (the path
# table's `ci-runs`), as src/.mandu-ci/suite-costs.json in the input tar, so
# the guest orders its queue by them (pipeline.sh passes run-suites --costs)
# rather than by the checked-in tables alone, which go stale unless someone
# regenerates them. Prints how many entries it holds; 0, and nothing
# appended, when the host has no such run (a fresh runner orders by the
# tables).
ci_append_costs() {
  local runs="$1" out="$2" last="${3:-10}" d n
  [[ -d "$runs" && ! -L "$runs" ]] || { echo 0; return 0; }
  d="$(mktemp -d "${TMPDIR:-/tmp}/mandu-ci-costs.XXXXXX")" || return 1
  if ! node "$CI_REPO_ROOT/scripts/suites.mjs" costs --all --last "$last" "$runs" > "$d/suite-costs.json" \
     || ! n="$(node -e 'process.stdout.write(String(Object.keys(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))).length))' "$d/suite-costs.json")"; then
    rm -rf "$d"; return 1
  fi
  if (( n > 0 )) && ! tar -rf "$out" -C "$d" --transform 's,^,src/.mandu-ci/,' --owner=0 --group=0 --numeric-owner suite-costs.json; then
    rm -rf "$d"; return 1
  fi
  rm -rf "$d"
  echo "$n"
}

# ci_source_tar <rev>|--worktree <out.tar> — the tree under test, every path
# under src/, plus src/.git (ci_append_git_dir). A commit is `git archive`
# (tracked files only); --worktree is the
# tracked files as they are on disk plus untracked files that are not ignored
# (never ignored files: no node_modules, no target/, no secrets.local.json).
ci_source_tar() {
  local src="$1" out="$2"
  if [[ "$src" == --worktree ]]; then
    ( cd "$CI_REPO_ROOT" && git ls-files -z -co --exclude-standard \
        | while IFS= read -r -d '' p; do [[ -e "$p" || -L "$p" ]] && printf '%s\0' "$p"; done \
        | tar --no-recursion --transform 's,^,src/,' --owner=0 --group=0 --numeric-owner \
              -cf "$out" --null -T - )
  else
    git -C "$CI_REPO_ROOT" archive --format=tar --prefix=src/ -o "$out" "$src"
  fi || return 1
  ci_append_git_dir "$src" "$out"
}

# ci_append_git_dir <rev>|--worktree <out.tar> — append src/.git: a one-commit
# shallow repository whose HEAD (detached) is the commit under test (HEAD for
# --worktree) and whose index matches that commit's tree. Suites that read the
# repository's own git state (`git rev-parse HEAD`, `git status`) then see the
# real commit, and a --worktree run's edits show as a dirty tree. Only that
# commit's objects travel (no history, no other refs, no hooks, no config
# beyond the defaults `git init` writes).
ci_append_git_dir() {
  local src="$1" out="$2" rev sha tmp rc=0
  rev="$src"; [[ "$src" == --worktree ]] && rev=HEAD
  sha="$(git -C "$CI_REPO_ROOT" rev-parse --verify --quiet "$rev^{commit}")" || return 1
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/mandu-ci-git.XXXXXX")" || return 1
  {
    git init -q "$tmp/repo" \
      && rm -rf "$tmp/repo/.git/hooks" \
      && git -C "$tmp/repo" fetch -q --no-tags --depth 1 "file://$CI_REPO_ROOT" "$sha" \
      && git -C "$tmp/repo" update-ref --no-deref HEAD "$sha" \
      && git -C "$tmp/repo" read-tree "$sha" \
      && rm -f "$tmp/repo/.git/FETCH_HEAD" \
      && tar -rf "$out" -C "$tmp/repo" --transform 's,^\.git,src/.git,' \
           --owner=0 --group=0 --numeric-owner .git
  } || rc=1
  rm -rf "$tmp"
  return $rc
}

# Values that go into job.env: a narrow character set, so the guest can read
# the file as data (KEY=value, one per line) without a shell. The command of
# --exec is the one free-form value; it travels base64-encoded.
CI_JOB_VALUE_RE='^[A-Za-z0-9_.,:/@+=-]*$'
CI_JOB_KEYS="MANDU_CI_MODE MANDU_CI_KINDS MANDU_CI_NEED MANDU_CI_ONLY MANDU_CI_JOBS MANDU_CI_RUN_ID MANDU_CI_SOURCE MANDU_CI_COMMIT MANDU_CI_REF MANDU_CI_IMAGE MANDU_CI_EXEC_B64 MANDU_CI_NETWORK MANDU_CI_OLLAMA MANDU_CI_CREDENTIAL MANDU_CI_INCLUDE_FLAKY MANDU_CI_INCLUDE_INTERNET MANDU_CI_LANE MANDU_CI_BUDGET MANDU_DEMO_IDS MANDU_DEMO_SIDES MANDU_DEMO_MODELS MANDU_DEMO_REPEAT MANDU_DEMO_JOBS MANDU_DEMO_AGENTS"

# ci_guest_budget <timeout> — the guest's budget (job.env MANDU_CI_BUDGET):
# the seconds of uptime by which its pipeline must be over, so that it ends
# its own run and writes its results before vm-run.sh's timeout kills it
# (continuous-integration.md §3). The timeout less a tenth of it, at most
# 150 s (writing the results disk and powering off); empty for a timeout
# under 60 s (no budget: the guest runs to the host's timeout).
ci_guest_budget() {
  local t="$1" margin
  [[ "$t" =~ ^[0-9]+$ ]] && ((t >= 60)) || return 0
  margin=$((t / 10)); ((margin > 150)) && margin=150
  echo $((t - margin))
}

# ci_render_job_env — print job.env from the variables named in CI_JOB_KEYS
# (unset → empty). Returns 1, printing the offending key, on a value outside
# CI_JOB_VALUE_RE.
ci_render_job_env() {
  local k v
  echo "# mandu CI job (scripts/ci/vm-run.sh); read by the guest's boot.sh as data"
  for k in $CI_JOB_KEYS; do
    v="${!k:-}"
    if ! [[ "$v" =~ $CI_JOB_VALUE_RE ]]; then
      echo "ci_render_job_env: $k has a character outside [A-Za-z0-9_.,:/@+=-]: $v" >&2
      return 1
    fi
    printf '%s=%s\n' "$k" "$v"
  done
}

# ci_read_pins <file> — set each KEY=value of pins.env as a shell variable.
# Refuses anything that is not a comment, a blank line or KEY=value.
ci_read_pins() {
  local line k v
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
    if [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9._:/+-]*)$ ]]; then
      k="${BASH_REMATCH[1]}"; v="${BASH_REMATCH[2]}"
      printf -v "$k" '%s' "$v"
    else
      echo "ci_read_pins: bad line in $1: $line" >&2; return 1
    fi
  done < "$1"
}

# ci_netns_bwrap — print a bwrap that can create a user + network namespace
# here (MANDU_CI_BWRAP, the PATH's, Mandu's granted copy; probed, not
# guessed), or return 1. A networked guest's qemu runs in such a namespace
# joined to slirp4netns --disable-host-loopback, so the guest reaches the
# internet and never the host's loopback (vm-image.sh's provisioning boot,
# vm-run.sh --network / --ollama; continuous-integration.md §4, §9).
ci_netns_bwrap() {
  local c
  for c in "${MANDU_CI_BWRAP:-}" "$(command -v bwrap 2>/dev/null)" /usr/lib/mandu/bin/bwrap; do
    [[ -n "$c" && -x "$c" ]] && "$c" --unshare-user --unshare-net --ro-bind / / -- /bin/true 2>/dev/null && { echo "$c"; return 0; }
  done
  return 1
}

ci_have_kvm() { [[ -r /dev/kvm && -w /dev/kvm ]]; }
ci_accel() {  # qemu acceleration arguments
  if ci_have_kvm; then echo "-enable-kvm -cpu host"; else echo "-cpu max"; fi
}

# The host's CPU for guests at once (continuous-integration.md §5.7): every
# guest vm-run.sh boots on this host, the runner's jobs and local runs alike,
# holds ceil(vCPUs / CI_SLOT_VCPUS) slots of a budget of the host's physical
# cores (MANDU_CI_HOST_VCPUS overrides; 0: no budget), so the guests never
# share SMT siblings over the cores: five 16-vCPU runner jobs plus local
# 32-vCPU runs on 64 cores made the same suites ~150 s slower (2026-10-17).
CI_SLOT_VCPUS=8
CI_SLOT_FDS=()
# ci_cpu_budget: the budget in vCPUs (empty: none).
ci_cpu_budget() {
  local v="${MANDU_CI_HOST_VCPUS-}"
  if [[ -n "$v" ]]; then [[ "$v" =~ ^[0-9]+$ ]] && (( v > 0 )) && echo "$v"; return 0; fi
  v="$(lscpu -p=core,socket 2>/dev/null | grep -v '^#' | sort -u | wc -l)"
  (( v > 0 )) && echo "$v"
  return 0
}
# ci_take_cpu_slots <dir> <vcpus> <budget> <wait s>: hold the slots (the
# open fds in CI_SLOT_FDS, released when this process and its children, the
# guest among them, are gone). One run takes its slots at a time (the
# acquire lock), so two never each hold half of what both need. Returns 1,
# holding nothing, when <wait s> passed first.
ci_take_cpu_slots() {
  local dir="$1" vcpus="$2" budget="$3" wait="$4" i fd mfd start=$SECONDS said=$SECONDS held=" "
  local total=$(( budget / CI_SLOT_VCPUS )) need=$(( (vcpus + CI_SLOT_VCPUS - 1) / CI_SLOT_VCPUS ))
  CI_SLOT_FDS=()
  (( total >= 1 && need >= 1 )) || return 0
  (( need > total )) && need=$total
  mkdir -p "$dir" || return 0
  exec {mfd}>"$dir/acquire.lock" || return 0
  flock -w "$wait" "$mfd" || { exec {mfd}>&-; return 1; }
  while :; do
    for (( i = 0; i < total && ${#CI_SLOT_FDS[@]} < need; i++ )); do
      [[ "$held" == *" $i "* ]] && continue
      exec {fd}>"$dir/slot-$i.lock" || continue
      if flock -n "$fd"; then CI_SLOT_FDS+=("$fd"); held+="$i "; else exec {fd}>&-; fi
    done
    (( ${#CI_SLOT_FDS[@]} >= need )) && break
    if (( SECONDS - start >= wait )); then
      for fd in "${CI_SLOT_FDS[@]}"; do exec {fd}>&-; done
      CI_SLOT_FDS=(); exec {mfd}>&-; return 1
    fi
    if (( SECONDS - said >= 60 )); then echo "vm-run: still waiting for host CPU ($(( SECONDS - start )) s; ${#CI_SLOT_FDS[@]} of $need slot(s))" >&2; said=$SECONDS; fi
    sleep 2
  done
  exec {mfd}>&-
  return 0
}

# The cache (images, the base image) and the prune rule.
ci_cache_dir() { mandu_path ci-cache; }
