# The guard's file identity: history rewrites and moved folders

Status: built (2026-10-16). Part of the confidentiality spine's §7.2a (the
committed bytes: git object-store twins, and the guard's backstop for locked
objects); split out of [`confidentiality.md`](confidentiality.md) so the
spine stays a summary. Code: `interceptors/net-supervisor/src/`
(`secret_open.rs` `by_identity`, `git_lock.rs`, `inode_pins.rs`,
`guard_kernel.rs` `judge_change`).

The guard knows a registered file by its path and by its `(dev, inode)`
(a hard link, a case spelling), and judges git object-store files by the
pack index beside them. Two situations broke those assumptions: a history
rewrite (git removes the twinned pack and its index), and a folder above a
protected file renamed by the agent. This note is how each is handled.

## 1. A history rewrite under the guard

A person asks the agent
to scrub a locked key from history: `git filter-repo --invert-paths --path
.env` (or `filter-branch`, then the reflog expired and `git gc
--prune=now`). The rewrite needs no locked byte (it rewrites trees), and
git's repack then removes the old pack, the one the launch twinned. A
kernel-lane probe found two guard defects there, both in the guard-only
and the bind posture:

- **A reused inode number taken for a removed registered file.** The
  guard matches a file it opened against the registered files by identity
  too (`SecretIndex::lookup_opened`: a hard link, a case spelling), from a
  list of their `(dev, inode)` re-`stat`ed at most every `ID_REFRESH` (2 s).
  The repack freed the twinned pack's inode, and on ext4 the next file
  created nearby gets the same number: for up to 2 s that new file was the
  pack's `object` entry, so its create was refused ("cannot create …:
  Permission denied" for the agent's next one or two files, and git's own
  `info/refs`, `objects/info/packs` and `commit-graph.lock` in the same gc,
  which then failed), and a read of it would have been handed the twin.
  Now the list keeps, with each identity, the status-change time (`ctime`)
  the inode had when it was listed, and a hit from a list that was not just
  built stands only when the opened file has that same `ctime` (the same
  inode, unchanged since it was listed, whatever name reaches it) or the
  registered path or its twin still has that identity
  (`secret_open::stale_hit_stands`, one `stat` each, asked only when the
  `ctime` differs); otherwise the list is rebuilt now and the file judged
  against it. A new file on a reused inode number has a later `ctime` and
  is not the registered path, so it is judged as itself. This is never
  weaker than before: every hit the old list gave for an unchanged inode
  still stands until the same 2 s rebuild that dropped it before, and a
  file that still is a registered file or its twin, under any name, still
  matches. The one hit dropped sooner than before is an inode whose status
  changed since it was listed and that the registered path and its twin no
  longer name: in the agent's tree that is a twinned pack's other hard
  link (made before the session) once git removes the registered name, and
  such a pack is judged by the backstop by its own index (LOCKED: refused).
- **The orphan index.** Git's repack unlinks an old pack's `.idx` before
  its `.pack`, and `git prune` then removes an `.idx` left without its
  `.pack`. Rule 4 refused both (LOCKED in the guard-only posture; UNKNOWN
  under the bind, where the pinned name is the bind-mounted twin), so the
  old index stayed, `git prune` warned "unable to unlink …idx", and the
  first refusal named the workspace in the end-of-session notice ("git was
  refused … start mandu in it") after a scrub that had worked. Two changes:
  - **An index whose pack is gone may be removed.** An unlink of an index
    is judged by what is at its pack's name in the directory the unlink
    acts on (`git_lock::removal_access`, an `fstatat(AT_SYMLINK_NOFOLLOW)`
    through the guard's pinned parent, so in the tracee's own view): no
    name there (ENOENT) and the index anchors nothing, so the unlink runs.
    Any name there (a pack, a twinned pack, a symlink, a directory) or a
    lookup that fails otherwise keeps the refusal. The guard never asks
    whether the pack there is twinned: it knows a twinned pack's inode by
    identity too, so a pack reachable under another name (a `git clone
    --local` hard link, made before the session) would count as twinned,
    and once git removes the registered name that other name is judged
    only by the backstop, by this index. So git's repack still cannot
    unlink a twinned pack's index first; its `git prune` removes it once
    the pack is gone. Why removing an orphan index is safe: an unlink reads
    nothing, and an index holds object ids, CRCs and offsets, never
    content; the locked ids are no secret (every tree that held the file
    names its blob's id, and `git log --raw` prints it). A pack appearing
    at that name after the check can only be one the agent could already
    read: a create carries bytes the agent holds, and a rename or link
    source is judged by rule 4 and the registered-secret rule (a LOCKED,
    UNKNOWN or registered pack never moves by its own name). A pack with
    no index stays UNKNOWN (refused), so `rm pack-X.idx; cat pack-X.pack`
    still reads nothing.
  - **Only a refused read is told as git refused.** The end-of-session
    notice, the `git-lock` read event ("read of … — REFUSED (git-lock: …")
    and the arbiter's `registerRepository` now follow only a refusal of an
    open or of a rename or link source (`git_lock::reported`): what keeps
    git from reading the repository and what a prepared copy fixes. A
    refused removal, replacement or truncate of an index keeps it anchored
    and stops nothing git needs (its repack ignores the failed unlink), so
    it is refused as before, names no repository in the notice and
    registers none, and is recorded on every refusal as its own
    `net_action` deny: "change of <index> — REFUSED (git-index: a change to
    a git index that lists a locked object …)"
    (`events::guard_git_index_change_refusal_event`), since that is what
    tampering with the anchor looks like.

After a scrub the end-of-session notice names no repository unless git
really was kept from a locked object: a bare remote the rewrite was
force-pushed to keeps the old, now unreferenced, object until a `git gc
--prune=now` there, so an agent that reads every object of it (`git
cat-file --batch-all-objects`) is refused and the remote is named,
correctly. The agent's checkout removing a protected file's real copy
(`.env`) is still refused ("unable to unlink '.env'"), by design.

Oracles: the unit tests
`a_removed_entrys_inode_number_reused_by_a_new_file_is_not_that_entry` and
`a_stale_hit_stands_on_an_unchanged_inode_or_a_registered_name`
(`secret_open.rs`), `an_index_is_removable_only_once_its_pack_is_gone` and
`only_a_refused_read_is_reported` (`git_lock.rs`),
`a_refused_index_change_is_recorded_as_a_change_never_as_a_refused_read`
(`events.rs`); the kernel e2e in
`tests/sandbox/git-history-locks.test.ts`: K16a (guard only) and K16b (with
the bind), the rewrite and gc succeed, every file created at once (72 in
three directories; in the CI guest, on ext4, git's own files and these
took the removed pack files' inode numbers) is made and reads back its own
bytes, no orphan index, no notice, the locked version unreadable before
and after and in no model request (without the identity fix K16 fails in
the gc itself); K17a and K17b, an index beside a pack twinned only by
identity (a `git clone --local` hard link) and one beside an untwinned
LOCKED pack cannot be removed (each refusal recorded as a `git-index`
event, none told as git refused), and once the pack is removed its index
can.

## 2. A registered file moved with its directory

The rule that keeps a registered file's real copy in place
(`registered_secret_refuses`: never renamed, linked, replaced or removed,
but for git's `object` and `deny` entries, which git replaces and removes)
judges the LEAF only, and a rename of a directory above it is not refused
unless a `protect:` or write-protect entry covers that directory. So the
agent can move a registered file under a new path (`mv ~/.aws ~/.aws2`, a
project folder holding a `.env`). Before 2026-10-16 the identity list kept
the moved file its entry only until its next rebuild (2 s), since the
registered path named nothing then, and in the guard-only posture a read
of the new path after that was the RAW file (a kernel-lane probe; under
the bind the twin is mounted on the file's own dentry and moves with it).
And in the NEXT session nothing knew the new path at all: a file a human
labelled (policy.yaml `paths:`) whose words no scan recognizes read raw
there, in both postures, and so did a derived copy moved with its folder
and not opened before the session ended (both reproduced in the kernel
lane). For an `object` entry the backstop already took over (a moved pack
is judged by the index moved with it: LOCKED, refused).

The maintainer's choice was to keep following the file, not to refuse the
agent's renames of every folder above one: this session holds it by its
inode (`interceptors/net-supervisor/src/inode_pins.rs`), and the arbiter
labels its new path for the next.

- **What is held.** Every registered entry but git's object store
  (`object`, `deny`) and the guard's own `derived` entries: a protected
  file (`kind` absent or `file`) and, fail closed as
  `registered_secret_refuses` treats it, a kind this guard does not know
  (`inode_pins::pinned_kind`). The guard opens each `O_PATH | O_CLOEXEC`
  (following symlinks, as the identity list's `stat` does) right after it
  loads the policy (`SecretIndex::enable_pins`), before its workers answer
  the agent's first trapped call (the rename family is trapped in every
  `secrets` launch, its write-protect list being never empty). While the
  descriptor is held the inode cannot be freed, so its number is never
  reused, and a `(dev, inode)` match is exact for the whole session:
  `by_identity` answers a held inode first, whatever names reach it. The
  descriptors are the guard's own: it is not dumpable (no
  `/proc/<guard>/fd/` from the agent's tree), and an open of one through any
  other path is the same inode, judged the same. Git's entries are not held
  (git removes and replaces them as it works, and the backstop covers a
  moved pack); twins live in Mandu's write-protected scope directory and
  never move.
- **When a pin is dropped.** At every identity-list rebuild (`plan`, pure):
  a held inode with no name left (`st_nlink` 0 on its descriptor: the file
  was deleted, or replaced by a rename over its last name) is released, and
  whatever the registered path names now is held. An editor's save through
  a temporary file and a rename (the person editing `~/.aws/credentials`
  outside the session) is followed this way, and until the rebuild the new
  file is the registered path itself (its path entry). A held inode that
  still has a name is kept, wherever that name is: moved with its folder,
  or a hard link made before the session to a file since replaced (it
  still holds the old secret). The agent cannot make such a name: a link,
  rename or removal of a registered file's real copy is refused.
- **A folder rename, atomically with the pins.** The rebuild is lazy (on a
  lookup, at most every 2 s), and a person's save can land between any
  check and the rename. So a rename that moves a directory (either side of
  a `RENAME_EXCHANGE`) runs inside `SecretIndex::rename_dirs_holding_pins`,
  under the identity lock: the pins are rebuilt, `renameat2` runs, and every
  registered file that was below a moved directory is held at its new path
  (`inode_pins::moved_path`, `PinSet::pin_moved`) before the lock is
  released and the call answered. A file there that cannot be held (past
  the budget) makes the guard undo the rename (`RENAME_NOREPLACE` back, or
  the exchange again) and answer EACCES. If that undo fails (the agent can
  make a name again where the folder was: `mkdir` is not trapped), the
  rename stands and every file it moved is known by its new path for the
  rest of the session (in-memory path aliases, `SecretIndex::add_alias`).
  A lookup that misses the pins waits for the lock and asks them again, so
  no open sees the moved file unheld. Why a lock and not a re-check alone:
  a re-check after the rename leaves a window in which a concurrent open of
  the new path is judged before the file is held; holding the identity
  lock closes it. Why it cannot deadlock the workers: the lock is taken
  after every judgement that can wait (an Inbox hold), and the rename
  itself takes no guard lock. For a tracee in a Landlock sandbox the rename
  runs on its mirror (`perform_under_domain`), and when the mirror pool is
  busy the guard waits for a mirror thread with the lock held
  (`landlock_mirror`): identity lookups that miss the pins stall for that
  wait, but the mirror's threads take no guard lock, so it always ends.
  Not holding the lock across that wait would reopen the window above, so
  the stall is the accepted cost. A folder that cannot be named
  (`/proc/self/fd` of its pinned parent) while pinning is on is refused.
- **The label follows the folder, after the rename stood.** The guard lists
  what a folder rename carries before it runs (`dir_follows`: every derived
  copy and every registered protected file below the folder, with its new
  path; the derived list read afresh first, labels minted in an earlier
  session included, and an arbiter that cannot be read refuses the
  rename). Only once the rename stood does it ask the arbiter to label the
  new paths (`label_follows`, `followDerivedLabel` "rename";
  `inode_pins::label_after_rename`): a rename refused before it ran, or
  undone because a file could not be pinned, leaves no label behind. Every
  carried label is asked, a failure does not stop the rest; if one cannot
  be recorded the rename is undone and the call answers EACCES. The labels
  already recorded for the other carried files then stay on the paths the
  undo vacated (the store cannot drop a row from the data plane): each is a
  derived row by reference to the moved file, so a later file at that path
  is only made stricter, never looser. If that undo fails too (the agent
  can make a name again where the folder was), the rename stands: the moved
  files are known by their new paths for the session (path aliases, the
  strictest derived label for a carried copy), and a moved protected file
  whose label could not be recorded is named at the end of the session
  (`movedNotice`, launcher `moved-files-notice.ts`: "a protected file was
  moved with its folder and Mandu could not record where", with its new
  path and how to give it a rule again; at most 20 named, and how many
  more; control and Unicode bidi formatting characters printed as spaces on
  both sides, so a path cannot reorder the line), since the next session
  would not know that path. The pins cover the session meanwhile, so labelling after
  leaves no gap. The next
  session's guard and the launch's discovery then know the new path. A
  launch with no arbiter mints no label; its pins alone cover the session.
  The arbiter takes a protected source too
  (`ArbiterServer.protectedLevelOf`: a human label, the catalog, or the
  secret registry) and records a derived row at the file's own level whose
  source is the file. **A follow never adds a destination.** A holder of a
  file may send where its label goes and where its registry rows go
  (`taintedProcessBindings`); a derived row's destinations are the
  intersection of its sources' (`label-lookup.ts` `byReference`). So: (1)
  a follow onto a REGISTERED file is refused (the row would give that
  file's label side its source's destinations, on top of its own registry
  rows; the agent names the target, and could aim at another registered
  file's path); (2) a row bound nowhere (no sources, or unknown ones) stays
  bound nowhere whatever a later raise or follow brings
  (`DerivedLabelStore.raise`): adding a source to a non-empty list only
  narrows the intersection, but `[]` → `[A]` would move the row from nowhere
  to A's hosts; (3) a new row's destinations are the moved file's own (its
  label and registry rows, by reference). A registered file going back to
  its own registered path (an exchange the agent reverses) needs no label
  there and asks none (`SecretIndex::is_held_at_home`: its held inode is
  that entry). Anything else a folder rename would put on a registered path
  (another registered file, a derived copy) refuses the rename with EACCES
  BEFORE it runs (`dir_follows`), not by an undo after it: the agent can
  make an undo fail (an untrapped `mkdir` of the old name, a concurrent
  rename during an exchange), which would leave one registered file's bytes
  under another's path. A carried path is skipped only when nothing is
  there (ENOENT, `inode_pins::carried_present`); any other error of its
  `lstat` (a folder above it the agent made unsearchable) refuses the
  rename, since that file may well move.
- **A path never lends its entry to another registered file's bytes.** As a
  backstop for a file the text lists did not see (one moved earlier, whose
  registered path no longer names it), a lookup whose PATH matches entry P
  but whose opened inode the guard holds for another registered path Q is
  answered with Q's entry (`SecretIndex::held_elsewhere`, in `lookup_opened`
  and `lookup_with`). The held inode is the stronger evidence (its number
  is never reused; the path is only where the file lies now), and Q's entry
  is the one that decides who may read those bytes and where they may go,
  so P's readers and destinations never apply to Q's bytes. Refusing the
  open instead would also keep them from P's readers, but would refuse Q's
  own; Q's entry is as closed as the bytes' own rule and no looser. When
  Q's own path still names that inode, P and Q are two registered names of
  one file (a hard link both were registered by): both entries are the
  file's own, and the stricter decides whichever name is opened
  (`stricter_entry`: the level, then the protected-file kind, then the
  smaller path; the pin is taken for the stricter name, so the answer never
  depends on which name was seen first).
- **The paths are matched as text, and a mismatch fails closed.**
  `dir_follows`, `protected_under`, `moved_path` and the pins' fix-up match
  the guard's view of the folder (`/proc/self/fd` of the pinned parents).
  When that text does not name the folder the tracee pinned (by identity),
  or the destination's parent, as with a bind visible only in the
  sandbox's mount namespace, and the folder holds a registered file or a
  derived copy (by identity: the folder is an ancestor of one), the rename
  is refused; with nothing below it, it runs and carries nothing. That test
  fails closed as the no-pin rule does (`protected_hit_by_ids_strict`): a
  listed file, or a folder above it, whose identity cannot be read counts as
  below the folder (a listed path with nothing there, ENOENT, is left out:
  it cannot be below anything).
- **The budget, and past it.** At most a quarter of the guard's soft
  `RLIMIT_NOFILE`, 16 to 4096 (256 at the usual 1024; the death watch's
  pidfds take another quarter); a launch registers a few to a few dozen
  protected files. A registered file that exists and is not held (past the
  budget, or its open failed) is listed `unpinned`, and a rename of any
  directory above it is refused (`judge_change`, `unpinned_hit`, its event
  "delete or rename of … — REFUSED in-kernel (protected-path: … could not
  hold by its inode …)"). That rule fails closed too: a folder that cannot
  be named, or a listed file (or a folder above it) whose identity cannot
  be read, refuses the rename and emits the same event
  (`protected_hit_by_ids_strict`). The guard says so on its stderr.
  `MANDU_NET_GUARD_PIN_MAX` lowers the budget (a test of the fallback); it
  never raises it.
- **The ctime-gated stale hit** (§1) stays for what is not held: the
  object-store entries (whose removal frees inode numbers git reuses at
  once) and a protected file past the budget. A held inode never reaches
  it.
- **A move to another filesystem** (`EXDEV`): `mv` copies, then removes. The
  copy reads the placeholder (every read of a registered file does), and
  the removal of the real copy is refused, so the real file stays.
- **Postures.** Pins are taken in the guard's view of the real files, so
  they hold in both; under the bind nothing else changes (the twin is
  still the mount on the file's dentry).

Oracles: `inode_pins.rs` unit tests (the budget, the kinds (an unknown one
held), the plan, `moved_path`, `pin_moved`; a real file held across a
directory rename, an editor's save and a deletion), `secret_open.rs`
`a_pinned_file_moved_with_its_directory_is_still_that_secret_after_any_rebuild`,
`a_save_over_the_file_racing_a_folder_rename_is_held_at_its_new_path` (and
its control: a plain rename loses the saved file),
`a_moved_file_that_cannot_be_held_undoes_the_folder_rename`,
`an_unknown_kind_is_held_and_an_object_entry_is_not`,
`the_unheld_rename_rule_fails_closed_when_an_identity_cannot_be_read`,
`past_the_pin_budget_the_file_is_listed_for_the_rename_refusal`,
`a_folder_rename_that_cannot_be_undone_leaves_its_files_known_by_their_new_paths`,
`only_the_held_registered_file_itself_goes_home_without_a_label`,
`a_registered_file_left_on_another_registered_path_is_judged_as_itself`
(the undo forced to fail: an exchange of two registered files left
standing; each path answers with the other file's entry, by its held
inode; its control without pins lends the path's entry),
`a_moved_file_left_unlabelled_is_written_to_the_notice`; launcher
`moved-files-notice.test.ts` (the notice's lines);
`inode_pins.rs`
`a_folder_rename_labels_only_after_it_stood_and_undoes_when_a_label_fails`;
`derived_index.rs` `the_labels_below_a_folder_are_listed_by_path_and_spelling`;
the arbiter's unit tests (`derived-label-program-gate.test.ts`):
`followDerivedLabel from a PROTECTED file`, `a raise never adds a
destination` (no sources and unknown sources absorb; known ones only grow)
and `a follow never widens a holder's destinations` (a target that is a
registered file is refused, no row written; a second follow onto a moved
copy adds no destination); the
kernel e2e `tests/sandbox/secret-moved-folder.test.ts`, guard-only, every
case checked against the production model proxy for a raw byte: M1
`~/.aws` and a project folder moved, past the 2 s rebuild both are
placeholders, and the arbiter holds labels for both new paths; M2 budget 0:
the renames are refused, any other folder moves, and no label was written
for a rename that did not stand; M8 a folder exchange that would put
one registered file on another's path (`app/.env` ↔ `lib/.env`) is refused
before it runs, either way round, while a move of the folder to a free path
runs;
M3 a person's save over the credential mid-session, then the move: the move
runs and the saved file is its placeholder; M4 the agent recreates the
registered path after the move: one placeholder copy, the real file
unchanged; M5 `RENAME_EXCHANGE` either way round (held: runs; budget 0:
EACCES); M6 a move to another filesystem; M7 a labelled file moved with its
folder is the placeholder this session and the next. And
`launcher/test/derived-label-live.test.sh` (9): a derived copy moved with
its folder, opened or not, is the twin in the next guard run. The negative
controls (run 2026-10-16): without pins M1 reads the raw credential;
without the rebuild before a directory rename M3 reads the saved file raw;
without the folder's label following M7 reads raw in the next session, and
(9) does for the unopened copy.
