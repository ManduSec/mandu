# Write protection: what the agent's process tree may not change

> **Status: BUILT 2026-09-28.** Decision note. Closes, on the guard's side,
> two gaps a sandbox security review found: the agent could rewrite Mandu's
> law and state on disk, and could write files that run later outside Mandu.
> The arbiter-side half (a relaxing policy.yaml edit made on disk waits for
> approval) is policy-surface.md §8.4.6. Decisions: the guard's open trap
> runs in every mode but `off`; files that run later are HELD and asked, not
> refused; policy.yaml `write_protect:` adds paths and opts out of built-in
> ones (§5); declining a held policy.yaml edit restores the file (§6); a held
> change's answer names the writer's binary, not its name, and a writer run
> with the agent's code loaded is refused (§2.1). §8 is the companion
> hardening of Mandu's OWN git, which reads repositories the agent can write
> from outside every sandbox.

## 1. The gap

The whole-agent wrap in the default `secrets` mode is a mask over the host,
not a jail, and in `injection` mode there is no wrap at all. So a program in
the agent's tree (a hostile `postinstall` run by a HumanShell `npm install`
is enough) could:

- rewrite `~/.mandu/policy.yaml`, which the arbiter reloads every 2 s,
  or `config.toml`, which the next launch reads, or the symbol DB with its
  persisted approvals (then `~/.mandu/mandu.db`, now `~/.mandu/state/mandu.db`,
  on-disk-layout.md §3), or the installed binaries
  the next launch runs (`~/.local/share/mandu`);
- write a file that runs LATER, outside Mandu: `~/.bashrc`, a systemd user
  unit, an autostart entry, `~/.ssh/authorized_keys`, a git hook;
- remove the arbiter's socket and bind an impostor in its place, which every
  interceptor would then dial.

## 2. The mechanism

The launcher builds a list (`launcher/src/write-protect.ts`) and adds it to
the guard's policy file as `writeProtect` (a policy file of its own when the
confidentiality axis is off). The guard (`mandu-net-guard`, seccomp user
notification, no privilege) then traps the open family and the delete and
write families (`MANDU_NET_GUARD_PROTECT=1`; since 2026-10-04 those families
are trapped under every guard policy file and the variable adds `bind`) and
judges, before the kernel acts, every:

- write-intent open (`O_WRONLY`, `O_RDWR`, `O_CREAT`, `O_TRUNC`, `O_APPEND`),
- a pathname Unix `bind` (it creates a file, and could plant an impostor
  arbiter socket),
- `rename`/`renameat`/`renameat2` (source and destination), `unlink`,
  `unlinkat`, `rmdir`,
- `link`/`linkat` (the file named and the new name), `symlink`/`symlinkat`
  (the new name), `truncate`, and x86_64's `creat` (an `open` under its own
  number that no filter had trapped before),
- `mknodat` and x86_64's `mknod` (the new name: a FIFO, socket, device or
  regular file), and the mode family `fchmodat`, `fchmodat2`, x86_64's
  `chmod`, and `fchmod` on a descriptor (the file whose mode changes; a
  read-only descriptor is enough for `fchmod`, so the write-open gate does
  not cover it),

whose target is an entry or lies below one. The target is matched by the path
the pinned descriptor names and by the files themselves
(`secret_open::write_protected_hit_pinned`: a hard link or a symlink leading
to a protected file, a bound or folded spelling of a protected directory).

**A name changed above an entry (2026-10-07, P0 (D)).** A rename (either
side), an unlink or `rmdir`, and a new `link`/`symlink` name AT A STRICT
ANCESTOR of an entry replace what the entry protects with no write under
it: `mv ~/.ssh ~/.ssh.old` then a planted directory renamed to `~/.ssh`
brought its own `config`, and a planted directory (or a symlink) put where
an entry's missing parent would be (`~/.orbstack` for an included
`~/.orbstack/ssh/config`) did the same. Such a change is judged as a change
to the entry below it (held or refused by that entry's answer), as
`protect:` already does for its paths (`guard_kernel::pinned_ancestor_write_hit`,
`secret_open::write_protected_ancestor_hit`): by path (the pinned parent's
path plus the name), and for an existing directory also by identity (a bind
or another spelling). A file's unlink, the common case, costs a string
compare only. Cost: renaming a folder that holds a protected path
(`~/.config`, a repository's `.git`, the workspace itself) now waits for
the human too.

**Entry forms (2026-10-07).** An entry's `form` says how its path names what
it covers (`secret_open::WriteForm`): absent, the path with its links
resolved and everything below it (every entry above); `name`, the entry
itself under its own name, a link included, and what is below that name (a
link on the arbiter socket's way, the runtime base's `current`: resolved,
the entry would have named the instance it points at and left the link free
to be replaced); `prefix`, every name in that directory that starts with the
last component (`.current.tmp-`, `dashboard-`); `self`, the entry itself
only (the runtime base: not renamed or removed, while what is in it stays
writable). The guard resolves only the directory of a `name`, `prefix` or
`self` entry, and matches one by the target's spelling and by identity
(`write_protected_hit_named`: the entry's directory under another spelling
holds a matching name, or the target IS the entry, unfollowed). A form this
guard does not know is the widest, the plain form. The runtime registries
(§9's last bullet, runtime-instances.md §2) are the entries that use them.

**A write-intent open is performed, never continued.** The
guard resolves it once in the tracee's view and judges what the walk
reached, pinned by a descriptor of its own, before anything changes
(`guard_kernel::pinned_write_hit`, `secret_open::write_protected_hit_pinned`,
the split open of `fs_supervisor::tracee::open_via`): an existing file by
the path its descriptor names and by its identity and its directories'; a
file about to be created by its pinned directory and name (and, when the
create finds a file already there, by that file too). `O_TRUNC` waits until
the opened file is known to be neither protected nor a registered secret
(`ftruncate`, regular files only): a truncating open of a secret's real path
(the guard-only posture has no bind) no longer empties it before the lookup
serves the twin. That holds whatever the access mode
(`secret_open::truncate_after_lookup`): Linux truncates `O_RDONLY|O_TRUNC`
too for an opener that may write, and until 2026-10-10 only a writable
access mode was held back, so a read-only truncating open of a secret's real
path still emptied it; the held-back truncation of a read-only descriptor
runs on a writable reopen of it in the tracee's Landlock domain. A reader
handed the real file has its `O_TRUNC` applied the same way, after the
refusals (`confidentiality-plan-10-flow-taint.md` §4.1 step 3). A write to a pseudo-filesystem file (a sysctl, a cgroup
file) is looked up again, the whole walk, by the context helper as the
tracee (`context_helper::lookup_as`), because the kernel judges such a
lookup by the opener: bwrap's own `max_user_namespaces` is its user
namespace's, not the guard's. Tests: kernel
`a_symlink_swapped_during_a_write_open_never_reaches_a_protected_file`
(a thread swaps the symlink while 400 opens write through it) and
`a_truncating_open_of_a_secret_never_truncates_the_real_file`, both failing
on the continued open; `a_read_only_truncating_open_of_a_secret_never_truncates_the_real_file`
(red before 2026-10-10, with a file that is no secret truncated as the
control); `a_pseudo_file_is_opened_with_the_tracees_namespaces_and_rights`.

**The name family is performed, never continued.** The same close for
`rename`, `unlink`/`rmdir`, `link`, `symlink`, `truncate`, `creat` and a
pathname `bind` (the path-change TOCTOU). Judged BY NAME and answered
`CONTINUE`, the kernel would re-resolve the path afterwards and a racing
thread could rewrite the path buffer or swap a symlinked parent directory
between the check and the kernel's resolve — winning, for example,
`rename(evil, ~/.mandu/policy.yaml)` (the arbiter reloads the law) or
unlinking the arbiter socket to bind an impostor. The guard
**performs each call on the tracee's behalf** and never `CONTINUE`s it
(`guard_kernel::handle_path_change_notif`, `perform_rename` / `perform_unlink`
/ `perform_link` / `perform_symlink` / `perform_truncate` / `perform_bind`):
each parent is pinned to an `O_PATH` directory descriptor resolved in the
tracee's view (`pin_parent`, the split `Via` resolution of
`fs_supervisor::tracee::open_as_tracee_via`; no performed open adds the
`O_NOCTTY` that `openat2` refuses with `O_PATH`, `performed_open_flags`,
2026-10-03); the judge runs on the pinned directory plus the leaf
(`judge_change`, `pinned_change_targets`, `secret_open::split_parent_leaf`);
and the mutating `*at` runs relative to the pinned descriptors with a one-
component leaf, so the kernel never re-resolves a parent a thread could swap.
A `truncate` resolves the whole path (symlinks followed) to a pinned inode,
refuses a registered secret, then `ftruncate`s a write reopen of exactly that
inode (`/proc/self/fd/N`). A rename source, a hard-link source and a truncate
target that resolve to a registered secret are refused (its bytes must not be
moved, hard-linked to a new name, or emptied out from under the twin); `creat`
routes to the write-open path above.

**A rename onto, or a removal of, a registered secret is refused** (with
`EACCES`, not an Inbox hold). Judging only the source side is not enough: in
the guard-only posture
(no twin bind, e.g. no `mandu setup`) any in-place writer the agent ran,
boxed or not — `sed -i`, `perl -pi`, an editor's save — read the twin,
wrote the placeholder text to a temp file and renamed it OVER the real
path, and `rm` removed the real file: the human's credential was replaced
by its placeholder or lost (data loss, not a leak). So a rename destination
(`Dest`) and a removed name (`Remove`, `unlink`/`unlinkat`) whose pinned
leaf is a registered secret's file, by path or identity, are now refused
like the source roles; under the twin bind the same calls already meet the
mount point (`EBUSY`), so both postures refuse. The rule by role and
entry kind is one pure function, `secret_open::registered_secret_refuses`
(called through `guard_kernel::pinned_secret_refuses` from `judge_change`,
`perform_truncate` and `perform_chmod`). Three edges, each deliberate:
the leaf is pinned without following, so a symlink TO a secret is a name of
its own (replaced or removed; the file is untouched); a `RENAME_EXCHANGE`
judges both sides as sources (refused already); and a git object-store
entry (`kind: object` or `deny`, launcher `git-object-twins.ts`) stays
git's to replace or remove (`git gc`, `repack`): a pack, a companion or a
loose object replaced or removed exposes and loses nothing, and the one
anchor, a locked pack's index, is kept by the git-lock rule
(`git_lock::refuses`). An unknown kind is refused (fail-closed). The fast
path that CONTINUEs a call no role could refuse now counts the unlink
family as secret-relevant too. Mandu's own twin and placeholder files are
written by the launcher before the agent starts, outside the agent's
filter, and are not judged. Tests: unit
`a_registered_secrets_file_is_never_replaced_removed_moved_or_emptied`;
kernel `a_rename_onto_or_unlink_of_a_secrets_real_file_is_refused`
(rename and `renameat2` onto the secret, `unlink` and `unlinkat` of it, all
`EACCES` with the real bytes intact; a symlink to it, an ordinary file and
an object-store entry still replaced and removed; it fails on the build
before this, where the rename replaced the real file); live
`launcher/test/secret-readers-live.test.sh` (4h) (the guard alone: `sed
-i`, `mv` onto and `rm` of a registered `.env` refused, the real file
intact, `sed -i` of an ordinary file still working). A pathname `bind` binds a `pidfd_getfd`
copy of the tracee's socket to the leaf, relative, on a thread whose cwd is
the pinned directory (`with_private_fs`: `unshare(CLONE_FS)`, `fchdir(pin)`,
the tracee's umask; binding `/proc/self/fd/<pin>/<leaf>` instead would refuse
a leaf that does not fit `sun_path` behind that prefix and make every socket
file 0777 under the guard's umask 0). Each
mutating step runs inside the tracee's Landlock domain, if it has one
(`perform_under_domain`, `landlock_mirror::Domain::run`), so its REFER /
TRUNCATE / MAKE_SOCK rights are honored and the guard never bypasses a sandbox
the tracee imposed on itself. **Identity comes from the pinned descriptors,
never from a path string re-resolved in the guard's view** (`leaf_identity`:
`fstatat(pin, leaf, AT_SYMLINK_NOFOLLOW)`; `pinned_dir_chain`: the `..` chain
of the pinned directory, in the mount tree it belongs to;
`secret_open::protected_hit_by_ids`), each `protect:` and write-protect entry
matched in the guard's view and in the tracee's (`/proc/<pid>/root`). A
spelling that exists only in the tracee's own mount namespace (a bind of a
protected folder) names nothing in the guard's view, so resolving there would
let `rm <bind>/tax.pdf` through (`launcher.secret-readers-live` pins it). The
guard fails closed (EACCES, or the tracee's
own errno) whenever it cannot act exactly as the tracee — a pinned fd that
names no path, `AT_EMPTY_PATH` on a `linkat` (it needs CAP_DAC_READ_SEARCH), a
socket or descriptor it cannot copy, a private cwd it cannot set up, or a
pseudo-filesystem truncate or chmod target; a withdrawn notification is
answered with nothing.

**`mknod` and the chmod family.** A node is a
new name: `perform_mknod` pins the parent, judges the leaf like a created
file (`NewName`), and runs `mknodat(pin, leaf, mode, dev)` with the tracee's
umask (`with_private_fs`, so a default ACL on the parent decides as the
kernel would) under its Landlock domain (the MAKE_* rights). A mode change
(`perform_chmod`, `secret_open::mode_call`) pins the file it changes: a path
resolved whole in the tracee's view (the final symlink followed, or not with
`fchmodat2(AT_SYMLINK_NOFOLLOW)`), or for `fchmod` and
`fchmodat2(AT_EMPTY_PATH)` a `pidfd_getfd` copy of the tracee's descriptor
(so a `dup2` after the check changes nothing). The judge (role `Mode`) runs on
that pinned file — a registered secret refused (its mode is not opened to
others or closed on the human), the write-protect list by path and identity
as for a write — and the mode is set on exactly it: `fchmod` on the copy,
`fchmodat2(fd, "", AT_EMPTY_PATH)` for a symlink or a descriptor, else
`chmod("/proc/self/fd/N")` (any kernel). **`fchmod` is judged, not left to the
write-open gate:** it needs only a read-only descriptor, so `open(O_RDONLY)`
then `fchmod(+x)` would otherwise arm a protected hook. A mode that is
already the file's is set without a judgement (`mode_change_is_noop`), so an
editor that re-applies a held file's own mode after an allowed write is not
asked twice. The kernel's own errnos come back as the tracee's (EBADF for an
`O_PATH` descriptor, EINVAL for unknown `fchmodat2` flags, EOPNOTSUPP for a
symlink's mode). Tests: kernel
`guard_refuses_a_chmod_or_mknod_of_a_protected_file`,
`an_unprotected_chmod_mknod_and_bind_are_performed_like_the_tracees_own`,
`a_chmod_racing_a_swapped_parent_never_changes_a_protected_file`,
`a_mknod_racing_a_swapped_parent_never_makes_a_node_in_a_protected_dir` (all
four fail on a guard that does not trap these); unit `mknod_and_mode_changes_are_name_family_calls_with_their_roles`,
`mode_call_decodes_every_form_and_refuses_unknown_fchmodat2_flags`,
`a_mode_change_to_the_files_own_bits_is_a_noop`,
`relative_unix_addr_holds_any_leaf_sun_path_can`; `guard_filter`
`mknod_and_chmod_are_trapped_with_the_write_family`; e2e
`write-protect.test.ts` (chmod and mkfifo of Mandu's own files refused, the
same elsewhere performed).

**Extended attributes.** `setxattr`,
`lsetxattr`, `fsetxattr`, `setxattrat`, and the `removexattr` family
(`removexattrat` too) are trapped and performed like the chmod family,
never CONTINUEd (`perform_xattr`; the pure rule in
`net-supervisor/src/xattr_change.rs`). The rule: a change of a registered
secret's file is refused, and a change of a file on the write-protect list
is judged like a write (`deny` refused, `ask` held for the human),
**whatever the attribute's name**; a change that changes nothing (the
file's own minimal ACL, the value it already has, removing a name it does
not carry) runs without a judgement; every other file's change runs as the
tracee asked. Every name, not only the POSIX ACLs, because
`system.posix_acl_access` is a mode change (`setfacl -m u::rwx` arms a
hook; a named-user entry opens the file to another local user), other
filesystems carry ACLs under other `system.*` names, a namespaced file
capability (`security.capability` v3) is a privilege, and an unprivileged
overlayfs reads `user.overlay.*`. "Refuse only what widens access" was
rejected: it needs each filesystem's ACL semantics right, and the no-op
exemption already covers what makes judging every change noisy (an editor
re-applying a file's ACL). The name and value are read once; the file is
pinned (a path resolved whole in the tracee's view, the final symlink
followed unless `l*` / `AT_SYMLINK_NOFOLLOW`, or a `pidfd_getfd` copy of
the tracee's descriptor), judged, and changed on exactly that file, through
`/proc/self/fd/N` for a path (an `O_PATH` descriptor refuses `f*xattr`). A
POSIX ACL's named user and group ids are moved into the guard's user
namespace first (`translate_acl_ids`), since the kernel reads them in the
caller's. The kernel's own argument checks (flags, name length, value
size, `struct xattr_args`) run in the kernel's order, so a bad call gets
the errno the kernel would give. Tests: unit `xattr_change` (the decode of
every form, name and size checks, the rule, the no-op test, ACL parsing and
id translation); kernel `guard_refuses_an_acl_or_xattr_change_of_a_protected_or_secret_file`
(fails on a guard that does not trap the family),
`an_unprotected_xattr_change_is_performed_like_the_tracees_own`,
`an_acl_racing_a_swapped_parent_never_changes_a_protected_file`,
`an_acl_racing_a_swapped_symlink_never_changes_a_protected_file`,
`an_acl_from_a_tracee_in_its_own_user_namespace_names_the_same_user`.

**Under every secret policy (2026-10-03).** The mode and attribute families
are trapped whenever a secret policy is in force, with or without a
write-protect list (since 2026-10-04 the rest of the write family, the
delete / rename family and the `mkdir` family are too: a holder's name or
attribute on a network or FUSE mount is refused unless bound, confidentiality
plan 13 §4.6; a non-holder's call is judged as before, a `mkdir` answered
at once; since 2026-10-07 `bind` is trapped under every secret policy
too, so a holder's socket file is such a name, and so are the owner and
timestamp families, which only a holder's call is judged in): a
`chmod` that would give a derived file (a copy a process holding a secret
wrote) any group or other bit, and a POSIX ACL set on one, are refused, so
the guard's narrowing of such files at the write-open is not undone
(confidentiality plan 13 §4.6, "Another local user"). Tests: `guard_filter`
`the_xattr_family_is_trapped_with_the_write_family`, kernel
`local_exits_integration.rs` (P).

Tests of the name family: kernel
`a_rename_racing_a_swapped_parent_never_replaces_a_protected_file`,
`an_unlink_racing_a_swapped_parent_never_removes_a_protected_file`,
`a_hard_link_racing_a_swapped_parent_never_links_a_protected_file`,
`a_bind_racing_a_swapped_parent_never_binds_under_the_arbiter_socket_dir`,
`a_truncate_by_name_never_empties_a_secrets_real_file` (all failing on the old
CONTINUE handler — the parent-swap flipper runs in the unfiltered supervisor
so it reliably hits the check→resolve window),
`a_rename_onto_or_unlink_of_a_secrets_real_file_is_refused` (above),
`an_unprotected_rename_unlink_link_symlink_truncate_is_performed_on_behalf`
(the positive: correct effect and errno, EXCHANGE and NOREPLACE semantics),
`a_rename_a_tracees_own_landlock_ruleset_forbids_stays_forbidden`,
`guard_refuses_changes_under_write_protected_paths_through_a_symlinked_parent`;
unit `pinned_change_targets_carry_the_parent_and_role_of_every_name_family_call`,
`split_parent_leaf_names_the_final_component_only`.

| Entry | Answer | Why |
|---|---|---|
| the Mandu home (`${MANDU_HOME:-~/.mandu}`, and the default `~/.mandu` when `MANDU_HOME` moves it) | refuse | everything Mandu stores: policy.yaml, config.toml, packs, the symbol DB, events, runs, caches (on-disk-layout.md §4). One entry, whose `except` carves out the frozen integrity modes' AgentView (and `full`'s `repo.git`) |
| `~/.local/share/mandu` and `$MANDU_PREFIX` | refuse | the installed package and its binaries, and the staged exec-box applier |
| `$MANDU_POLICY_FILE` | refuse | a policy file kept outside the home |
| an OpenCode launch's `<scope run dir>/opencode-config` | refuse | OpenCode 2's only config directory under Mandu (the launcher's run file and links; supported-agents.md §2.3 item 8): OpenCode 2 reloads its config mid-session, and a model endpoint written there would take the next request around the proxy |
| every launch's `<scope run dir>/sdk-route` and `<scope run dir>/sdk-shims` (2026-10-18; sdk-route.ts `sdkRouteWriteProtect`) | refuse | the SDK route's file and the copies of the preload and the Python hook that read it, and the PATH shims (agent-sdks.md §3.6): a route the agent wrote there would hand an agent CLI a host starts a model base URL or proxy of its choosing, and a replaced shim would run that CLI unrouted. On the macOS profile too |
| shell startup files (`~/.bashrc`, `~/.profile`, zsh's, fish's config dir) | ask | run by every new shell |
| `~/.config/systemd/user`, `~/.local/share/systemd/user` | ask | services systemd starts |
| `~/.config/autostart` | ask | programs the desktop starts |
| `~/.config/environment.d`, `~/.pam_environment` | ask | environment of every login |
| `~/.ssh/authorized_keys{,2}`, `~/.ssh/config`, `~/.ssh/rc` | ask | who may log in; `ProxyCommand`; login commands |
| every file ssh reads through an `Include` of `~/.ssh/config` (the launch's home's and the account's, which ssh reads from the password database) or of `/etc/ssh/ssh_config`, followed to ssh's depth (16): a plain word, its file (existing or not); a glob pattern, the deepest directory before its first glob character; and the account's own `~/.ssh/config` when `$HOME` is another (P0 (D), 2026-10-07; `launcher/src/ssh-config-includes.ts`) | ask | ssh reads a key raw (plan 13 D8 (12)), and a configuration file decides what it opens: `Include ~/.ssh/id_ed25519` in an included file makes ssh print each line of the key as a bad keyword (OpenSSH 10.2), and `PKCS11Provider` / `SecurityKeyProvider` load a library. Label "an ssh setting". An include too broad to hold (the home or above it, a top-level directory such as `/tmp`, `~other/…`) is a launch warning instead (§4) |
| `~/.gitconfig`, `~/.config/git/config` | ask | `core.pager`, `core.fsmonitor`, aliases |
| the workspace repository's hooks dir (a linked worktree's common dir) | ask | run by git on the human's next commit |
| OpenCode's plugin and custom tool dirs (`plugin`, `plugins`, `tool`, `tools`) in the user's global config dirs (`$XDG_CONFIG_HOME/opencode`, and `$OPENCODE_CONFIG_DIR` when set), in `~/.opencode`, and in each `.opencode` from the cwd up to the repository root (the cwd's alone outside one) | ask | modules OpenCode imports into its own process at its next start, outside Mandu, or under it with an opt-in (supported-agents.md §2.3 items 11 and 12); label "an OpenCode plugin or tool" |
| the user's OpenCode settings files that can name a plugin: `opencode.json`, `opencode.jsonc`, `config.json`, `tui.json`, `tui.jsonc` in the same three user dirs, and an absolute `$OPENCODE_CONFIG` | ask | a `plugin` list names npm packages the next OpenCode session imports (supported-agents.md §2.3 item 12); label "an OpenCode setting". OpenCode 1's own `$schema` edit is made by the launcher before the launch, so OpenCode's start is not held; its other writes (a settings save, its TUI plugin manager, a one-time `tui.json` migration) wait for the human |
| the arbiter's data socket, its real path, and each symlink on the way (`mandu/current`) | refuse | removing it and binding an impostor there would answer "allow" to every interceptor; not its directory, which a test or dev arbiter may share with the agent's files |

A refusal answers `EACCES` and emits a `net_action` event naming the entry.
An `ask` asks the arbiter (`decideProtectedWrite`): a prior human verdict for
(program, file) decides; otherwise a pending Inbox row (`write:<exe>#<sha256>`
× path, §2.1; the same allow once / always / deny as a held secret read) and the
guard keeps the call suspended, asking again every 500 ms, up to the hold's
ceiling (`MANDU_SECRETS_ASK_TIMEOUT`, 60 s by default), then refuses. The
row outlives the hold, so an answer given later applies to the next attempt.
An unreachable arbiter, or an answer the guard does not know, is a refusal.
The Inbox shows only labels the launcher writes (`arbiter/policy/write-protect.ts`;
the data socket is reachable from the agent's tree, so a caller cannot put
its own words in front of the human).

### 2.1 The program is its binary

A verdict keyed by the writer's basename (`write:vim`) is not safe: answering
*Always* (or *Allow once*) to `/usr/bin/vim` changing
`~/.ssh/authorized_keys` would admit any binary named `vim`, so an
agent-written `/tmp/x/vim` could add a key, or spend the `once` the human
gave the real editor. The rule, mirroring the held secret open
(confidentiality-plan-13-reader-set-labels.md §3 D8):

- **The key is the binary.** The guard reports, with every `ask`, the
  writer's identity facts as it does for an opener
  (`reader_identity.rs`: `IdentityCtx::exe` and `findings`): the resolved
  `/proc/<pid>/exe`, the sha256 of the inode it runs (hashed through
  `/proc/<pid>/exe`, cached by inode), whether that inode and every
  directory above it are out of the agent's reach (`exeSystem`), and the
  loader and interpreter variables set to a value the launch did not give
  plus `code:<path>` for each agent-writable executable file mapped into it
  (`openerEnv`). The verdict and its Inbox row are keyed
  `write:<exe>#<sha256>` (`writeVerdictSubject`, the same
  `binaryVerdictSubject` as D8's `open:` key): another path or a rebuilt
  binary is another question. Without a hash (a file the guard cannot read)
  the path alone keys it, as a pin without `sha256` matches by path; the
  subject is one-to-one, so a file named `/w/tool#<hash>` never spells the
  key of `/w/tool` with that hash. A hash that is not 64 hex digits, or no
  absolute executable path, is refused.
- **An unclean writer is refused, not asked.** A writer run with a loader
  or interpreter variable the launch did not give (`LD_PRELOAD`,
  `PYTHONPATH`, …), with an executable file the agent could have written
  mapped in, or whose environment the guard did not report (an older
  guard; a process it could not read) is not the program a human would be
  answering about: the arbiter refuses it (`EACCES`) with the reason, and it
  neither matches nor spends a prior answer and files no Inbox row. This is
  D8's choice for an opener ("no reader, spends no once, never prompted"),
  and here it is the only safe one: a row saying "/usr/bin/vim wants to
  change ~/.bashrc" for a vim that runs the agent's preloaded library would
  put the agent's code behind the human's *Allow*.
- **Where the program lives is said, not decided on.** A writer whose
  binary the agent could have written (`exeSystem` false) is still asked:
  the human sees its path, and the Inbox sentence adds "The agent could have
  written this program." (D8 asks the human about such an opener too; it
  only refuses to pin it on first use, which writes do not have.)
- **Old rows stop matching.** A row recorded under a basename key matches no
  writer, so each program is asked once more.
- **What the human sees.** The dashboard's Inbox (`home.ts` `describeAsk`,
  the inspector's `approvalSentence`) and `mandu why <path>` ("decided
  /usr/bin/vim changing it: approved (always)", on any level and with the
  secrets axis off) show the path; the hash stays in the key.

Tests: `arbiter/test/unit/protected-write.test.ts`
(an approved `/usr/bin/vim`, always and once, admits neither `/tmp/x/vim`
nor a rebuilt vim; vim with `LD_PRELOAD`, with `code:` mapped, or with no
reported environment is refused with no row and spends nothing; an old
`write:vim` row matches nothing; the `path#hash` spelling),
`flow-taint.test.ts` (`binaryVerdictSubject` is one-to-one),
`tests/stack/writer-identity.test.ts` (the same over the production
`ArbiterClient`, axis on and off, and `whyPath` by path), and
`tests/sandbox/write-protect.test.ts` under the real guard (after *Always*
for the system's `tee`, a copy of it in the workspace is held under its own
row and refused unanswered; the system's `tee` with `LD_PRELOAD` is refused
with no row; the system's `tee` still goes through).

**A writer that runs code is named with its script** (confidentiality-plan-13
§8 decision (c)). A shell or an interpreter answered *Always* would otherwise
admit whatever it ran next. The guard reports, with every `ask`, the script
such a writer runs (`script_identity.rs`, R5's facts, as for an opener),
and the key names it: `write:<exe>#<sha256>#script:<path>#<sha256>`, so
allowing python3 running `/opt/tools/fix.py` allows neither another script
nor `python3 -c`. A writer running no script those checks pin (inline code,
`bash -c 'echo … >> ~/.bashrc'`, the agent's own shell, a script it could
write) gets no reusable answer: its row names its process,
`write:<exe>#<sha256>#run:<procKey>`, the answer covers that run's change
(an *Always* is kept as once), and the next change asks again; the Inbox
says so ("Your answer covers this change only"). A row naming the
interpreter alone matches nothing and is shown as no longer applying. Tests:
confidentiality-plan-13 §3 D8's decision (c) bullet.

**An editor, and a program handed code by its command line**
(confidentiality-plan-13 §3 D8, "Code by argument"). Off the code-running
list, an *Always* for `/usr/bin/vim` changing a protected file would admit
whatever vim was told to run next (`vim -c`, a modeline, a
vimrc or plugin the agent wrote). Editors, debuggers and tracers (`vim`,
`nvim`, `ex`, `emacs`, `ed`, `gdb`, `strace`, `sqlite3`, …) are on it,
so their change is keyed by its run like a shell's: asked per change, an
*Always* kept as once, and an older *Always* for vim shown as no longer
applying. A writer whose command line or environment hands it code (the
guard's `args:` findings: `git -c core.editor=…`, `sed -e '…e…'`) is keyed
the same way. Utility cost: a human who edits a protected file through the
agent's vim is asked each time. Tests: `protected-write.test.ts` (vim per
run), `arbiter/test/component/args-code-reader.test.ts` (a git writer
handed code).

The open trap this needs is on in every mode but `off`: about 25 µs per open
(confidentiality-plan-10-flow-taint.md §7.1), already paid by the default
`secrets` mode. `MANDU_WRITE_PROTECT=0` turns the whole list off for a
launch. policy.yaml `write_protect:` adds to the list and drops entries from
it (§5).

**The arbiter itself.** A program in the tree that removed the arbiter's
socket and bound its own in its place would be dialed by every interceptor,
so an impostor answering "allow" or "raw" would turn fail-closed into
fail-open. With the socket, its real path and the `current` link refused, and
a pathname bind pinned and performed on the tracee's behalf like any new file
(§2, never re-resolved), that is not possible where the guard runs. Killing the arbiter is not possible where the twin
wrap runs: it gives the tree a pid namespace of its own (`--unshare-pid`,
exec-routing.md §7.5). Where the guard alone serves the twins (no user
namespace for the wrap) a kill is still possible, and fails closed.

**Mandu's runtime registries (2026-10-07).** The Linux list carries the
entries the macOS profile denies (§9's last bullet): under the launch's
runtime base and the account's default base and rendezvous,
`instances/`, `dashboards/`, `vm-guests/`, `logs/`, `test/`, `release-check/` and the human
plane's `human/` (plain), `current`, the legacy `arbiter.sock` and
`dashboard.log` (`name`), `.current.tmp-` and `dashboard-` (`prefix`), and
the base itself (`self`), all `deny` under Mandu's own label, so policy.yaml
cannot drop them (write-protect.ts `runtimeRegistryProtect`; runtime-instances.md
§2, "planted paths"). Mandu processes outside the agent's confinement (the
arbiter's sweep, the dashboard, `mandu reap`, the launcher, the supervisor)
write through and delete from these, so the agent may not plant anything
there. A registry that would hold the workspace or the scope dir refuses
the launch. Not judged: a new directory (`mkdir`, below in §4). Test:
`tests/sandbox/write-protect-registry.test.ts`.

## 3. Left out, on purpose

- **A repository's `.git/config` and `~/.claude/settings.json`.** Both are
  written legitimately and often (`git push -u`, `git remote add`; Claude
  Code saves its own settings), so holding them would ask about ordinary
  work. Both can name a program that runs later (`core.hooksPath`,
  `core.fsmonitor`, from git 2.54 a config-based hook,
  `hook.<name>.command`; a Claude Code hook), which is the residual
  `docs/guarantees.md` names. Note that `core.hooksPath` also moves the
  hooks directory out from under the protected one, and a config-based
  hook needs no file in any hooks directory at all. Mandu's OWN git on such
  a repository starts none of those programs (§8); the residual is the
  human's git.
- **A project's OpenCode config documents** (`opencode.json(c)` in the
  workspace). They can name an npm plugin, but the agent edits the
  workspace in ordinary work, and a project's plugin list does not run
  under Mandu by default (supported-agents.md §2.3 item 11). The user's
  global ones are held since 2026-10-07 (§1, item 12).
- **OpenCode's cache and the global directory's package files**
  (`~/.cache/opencode`, `~/.config/opencode/package.json`,
  `node_modules`). OpenCode installs into them at its start; a change there
  matters only to a plugin that runs, which under Mandu takes an opt-in.
- **Other files that run later** (editor init files, IDE task files, a
  shell's per-directory hooks such as `.envrc`). The list covers what runs
  without the human opening a particular tool; it is not exhaustive.

## 4. Residuals

- **Closed:** `mknodat`/`mknod`, the chmod family and the extended
  attribute families (with the Linux 6.13 `*at` forms) are trapped and
  performed pinned (§2).
- **A chmod of a pseudo-filesystem file is refused** (a cgroup or sysfs
  attribute; the guard would act with its own view of the namespaces), as a
  truncate is. A tree that delegates cgroups to itself by `chmod` fails.
- **The guard must run.** In the `gated` posture, or on a host without
  seccomp user notification, nothing is protected, as for secrets.
- **A new directory is not judged.** `mkdir` under an entry is not on the
  list (the guard traps it only for a secret holder's name on a remote
  mount, §2 "Under every secret policy"): the agent can make an empty
  directory there, though nothing in it. Under the runtime registries
  (§2, "Mandu's runtime registries") its only effect is a refused start
  (an instance id or a promotion's temp name already taken).
- **Host services outside the tree** (`systemd-run --user`, the D-Bus
  session bus) run code outside the guard, which can write these files; the
  agent's road to them is closed separately by the AF_UNIX allow-list
  (exec-routing.md §4.2).
- **An ssh `Include` too broad to hold** (`Include ~/*.conf`, `Include
  /tmp/*.conf`, an `Include` of another account's home): holding it would
  hold the home or a top-level directory, so the launcher warns at launch
  and leaves it writable; ssh may then read a file the agent wrote as its
  configuration (2026-10-07, P0 (D)). A program the human vouches for with
  `prints: nothing` reads its own configuration files, which Mandu does not
  know (plan 13 §3 D8).
- **A relaxing policy.yaml edit made while the arbiter is down**, that no
  Inbox row names, applies at its next start (the arbiter-side half). One a
  human declined, or one still waiting, does not (§6).

## 5. Your additions and opt-outs: policy.yaml `write_protect:`

The human's law file adds to the list and drops entries from it
(`arbiter/policy/guard-settings.ts`; the launcher reads the compiled lists
from the arbiter at launch, the `guardSettings` op, and expands `~`):

```yaml
write_protect:
  deny: [~/bin]                        # refused, like Mandu's own files
  ask: [~/.config/nvim/init.lua]       # held for your OK in the Inbox
  unprotect: [~/.gitconfig]            # a built-in "runs later" entry dropped
```

- `deny` and `ask` entries use the two answers that exist, with the label
  "a file you protected in policy.yaml" (the Inbox sentence says you asked to
  decide each change). The guard takes the first entry a path falls under,
  so the order is the precedence: Mandu's own files, then your `deny`
  paths (a `deny` can harden a built-in `ask`), then every `ask`.
- `unprotect` drops a built-in `ask` entry by its exact path (after `~`
  expansion); a path below a built-in directory entry does not carve it out,
  and a value that matches no entry is logged and does nothing. The repo
  hooks entry can be dropped by naming that repository's hooks directory.
- **Mandu's own files cannot be unprotected.** The validator refuses a value
  that names the Mandu home (anything under `.mandu`, or under the
  relocated `$MANDU_HOME`), the install or runtime directory (`mandu` under
  `.local/share`, `/usr/lib`, `/usr/local/lib`, `/opt`, `/etc`, `/var/lib`,
  `/run/user/<uid>`), a symbol DB file, `arbiter.sock`, or a directory above
  them (`~`, `~/.local`, `~/.local/share`, `/`). And the launcher never
  removes an own-files or arbiter-socket entry, whatever the value says, so a
  custom `MANDU_PREFIX` the validator cannot see is covered the same way.
- Adding a `deny` or `ask` path TIGHTENS the law and applies at once;
  removing one, a `deny` becoming an `ask`, and every `unprotect` entry
  RELAX it, so a disk edit that does so waits for a human in the Inbox like
  every relaxation (policy-surface.md §8.4.6). No edit op of the policy
  agent or the Describe box names these keys, so a model cannot propose
  them.
- A failed read (an older arbiter, a timeout) gives the built-in list with a
  warning: the opt-outs are then absent (tighter) and only the added paths
  are lost for that launch, like `protect:`.

## 6. A declined policy.yaml edit: the file is restored

The arbiter holds a relaxing policy.yaml edit made on disk until a human
decides (policy-surface.md §8.4.6). Were a DECLINED edit to stay in the
file, the next arbiter start would load it as the law: the "no" would last
only until a restart. **Decision: deny restores the file** (`arbiter/policy/policy-restore.ts`), so policy.yaml
always matches what is enforced.

- **On deny**, the arbiter writes the content in force back: a temp file in
  the same directory with the file's permission bits, then a rename. A
  declined removal re-creates the file. The restore is audited as a
  `config_change` with `via: restore` on the arbiter-admin stream. The
  Inbox row keeps the declined text (`diskText`, admin channel only: the
  data plane never reads a hand edit), so the edit can be recovered.
- **Only while the file still holds the declined bytes.** A newer edit that
  landed before the human's click is judged as a fresh edit (applied, held
  anew, or refused), never overwritten. The hash is checked again right
  before the rename; an edit landing in the few system calls between that
  check and the rename is the one race left.
- **The restore is not a foreign edit.** The arbiter remembers the bytes and
  the stat identity it wrote, so the poll does not judge its own write.
  Declined content written again later is restored again, with no new card.
- **At start.** The arbiter records the content in force per file path in
  mandu.db (`policy_enforced`). At start, a file that differs from it and
  that a DENIED Inbox row names is restored before it is loaded; one a
  PENDING row names stays held (the recorded content is the law, the same
  card waits). A start that cannot write the file still keeps the declined
  content out of force and retries on every poll. A recorded content that no
  longer validates refuses the start rather than load the declined file;
  any edit of the file gives it a new hash, and it then loads as the law.
- **Left as it was:** an edit made while the arbiter is down that no row
  names is the law at start (§4).

## 7. Tests

- `net-supervisor` unit: `write_protected_hit` (path, below, hard link,
  symlink, bound parent), `write_targets`, the policy file, `resolve_existing`;
  `guard_filter`: the write family trapped with the delete family, mknod and
  the chmod family by number; `mode_call`, `mode_change_is_noop`,
  `relative_unix_addr`.
- `net-supervisor` kernel (`guard_integration.rs`
  `guard_refuses_changes_under_write_protected_paths`): twelve ways of
  changing a protected path refused, reads and writes elsewhere allowed;
  `guard_refuses_a_chmod_or_mknod_of_a_protected_file`,
  `guard_refuses_an_acl_or_xattr_change_of_a_protected_or_secret_file`, and
  the name-family, chmod and xattr race and perform-on-behalf tests of §2.
- `arbiter/test/unit/protected-write.test.ts`: the hold, once / always /
  deny per (program, file), the ceiling, a foreign label, the admin-only
  answer.
- `launcher/test/unit/write-protect.test.ts`: the list, XDG and overrides,
  worktree hooks, the policy file merge. `ssh-config-includes.test.ts`:
  ssh's `Include` rules (words, `~`, relative words, globs, nesting, the
  system file), the broad ones warned, the opt-out.
- `net-supervisor` unit `a_name_change_at_an_ancestor_of_a_write_protected_path_hits_it`
  and kernel `guard_refuses_replacing_an_ancestor_of_a_write_protected_path`
  (red before: `~/.ssh` moved aside, a planted directory put in an entry's
  missing parent's place). `tests/sandbox/guard/ssh-config-write-protect.test.ts`:
  the production list for a HOME with ssh includes, under the real guard and
  a real arbiter: a new or changed included file, `~/.ssh` moved aside and a
  planted parent are refused at the ceiling, an ordinary file written. `guard-settings.test.ts`: the
  `guardSettings` read and its failure, `deny` ahead of the built-in asks,
  `unprotect` by exact path, never an own-files entry.
- `arbiter/test/unit/guard-settings.test.ts`: validation (own files refused
  as opt-outs in every known spelling), the relax / tighten proof, a disk
  opt-out held, no edit op reaching the keys. `policy-restore.test.ts`: the
  pure restore and start decisions, deny restoring the file (mode kept, a
  removal re-created), a racing edit judged fresh, restarts over a real
  mandu.db (restored before loading, a failed restore still out of force, an
  unnamed edit the law, no record the file).
- `tests/sandbox/sdk-route-protected.test.ts` (2026-10-18): the real
  launcher and guard in `secrets` mode, `--target claude -- node host.js`:
  the host's rewrite or removal of the SDK route's file, a file beside it,
  a change to the preload or Python hook copy, the folder renamed, a shim
  replaced or removed are all refused, a file elsewhere in the scope run
  dir is written, and the claude the host starts is still routed.
- `tests/sandbox/write-protect.test.ts`: the real launcher,
  guard and arbiter in `injection` mode; policy.yaml append and rename
  refused, a `.bashrc` append held and allowed once, the next one refused at
  the ceiling. `write-protect-labels-parity.test.ts` pins the label sets.
  `policy-restore-and-guard-settings.test.ts`: a declined relaxation
  restored on disk and not the law after a restart (real ArbiterServer, the
  admin channel), a disk opt-out held until approved, and the real guard
  honoring a policy.yaml socket extra, deny path and opt-out.

---

## 8. Mandu's own git on repositories the agent can write

**Decision note, BUILT (2026-09-30).** Code: `launcher/src/hardened-git.ts`
(copied byte-identical to `arbiter/src/`, `dashboard/src/`, `fs-sync/src/`),
`launcher/src/git-object-twins.ts` `worktreeBlobNames`,
`arbiter/ipc/instance.ts` `gitRevOf`, `arbiter/policy/prepared-copies.ts`
`prepGit` (confidentiality-plan-14 §11.1 R3). Tests: §8.7.

### 8.1 The problem

The launcher, the arbiter, the dashboard and fs-sync run `git` **outside
every sandbox**, on repositories an agent can write: the workspace, and any
repository a data-plane op names (`registerRepository`, `scanSecretHistory`,
`suggestPolicy`, `gitHistoryLocks {roots}`), which the agent's tools can call.
A repository's own config (`.git/config` and every file it includes) and its
attributes (`.gitattributes`, `.git/info/attributes`) can name **programs git
runs**. An agent in a confined session writes `.git/config` freely (it is
left out of the write guard on purpose, §3 above), so a
program it plants there would run UNCONFINED the next time Mandu's own git
read the repository: at the next launch, the next scan, the dashboard's next
refresh. That is a sandbox escape.

Two such vectors were found first (`core.fsmonitor`, an index read;
`log.showSignature`, which hands every signed commit a `git log` shows to
`gpg.program`). This section is the full audit (§8.2), the one fix every call
site shares (§8.3), the working-copy hash that could not be fixed by a flag
(§8.4), the sandbox added behind it (§8.5), what stays open (§8.6) and the tests
(§8.7).

The human's own git on the workspace is out of scope here: a program the
agent plants for it is the residual §3 above and
`docs/guarantees.md` name.

### 8.2 The audit

Every git invocation Mandu's runtime code makes. "Writable" is whether an
agent can write the repository's config or attributes.

| Call site | Runs in | Repository | Writable | Subcommands | Reachable without the hardening | Now |
|---|---|---|---|---|---|---|
| `launcher/src/git-object-twins.ts` `defaultGitRunner` (launch prep: `protectedBlobsOf`, `labelledBlobsOf`, `historyStateOf`, `objectDirsOf`, `buildPack`) | launcher, every launch in `secrets`/`full` | each repository holding a protected file or reached by a label; the workspace | yes | `log --raw --stdin`, `rev-list --no-walk` (`--all`; `--ignore-missing --stdin`; `--all --reflog` on a doubt), `rev-parse` (one call per work tree), `config --get-regexp` (one per work tree), `for-each-ref`, `ls-files -s`, `hash-object`, `pack-objects`, `index-pack`, `version` (only where no git sandbox probe printed it); and it reads the reflog files itself (`reflog-tips.ts`: plain directories and regular files only, each opened `O_NOFOLLOW`/`O_NONBLOCK`, capped; what it reads reaches git only as object names on stdin) | **the clean filter (`hash-object` of the working copies)**, the lazy fetch of a partial clone (any object read), inherited `GIT_*`; `fsmonitor` and `showSignature` | hardened (§8.3), `worktreeBlobNames` (§8.4), sandboxed (§8.5) |
| `launcher/src/placeholder-commits.ts` (`preparePlaceholderWatch`, `checkPlaceholderRepo`; through `defaultGitRunner`) | launcher: at launch in `secrets`/`full` (Linux; each call 5 s at most), after the agent exits, and at the next launch for a crashed one | each repository holding a twinned file in its work tree (tracked, untracked or ignored) | yes | at launch `ls-files -s` and `rev-list --all --no-walk` only; at the check `ls-files -s`, `rev-list --all --no-walk`, `log --raw -m --full-history --ignore-missing --stdin`, and on a hit `rev-parse -q --verify HEAD`, `symbolic-ref -q HEAD`, `show-ref --verify -q`, `ls-tree -r HEAD`, `for-each-ref --contains` (no working copy is hashed: the twins' ids are computed in the launcher; no blob is read) | inherited `GIT_*`; `fsmonitor` (the index reads), `showSignature` (`log`) | hardened (§8.3), sandboxed (§8.5) |
| `launcher/src/net-guard-setup.ts` `readGitRemotes` | launcher, with the net guard | workspace | yes | `config --get-regexp` | inherited `GIT_*` (a config read starts nothing) | hardened |
| `launcher/src/revert-command.ts` `gitRoot` | `mandu revert` | the cwd's repository | yes | `rev-parse --show-toplevel` | inherited `GIT_*` | hardened |
| `launcher/src/doctor.ts` `gitVersion` | `mandu doctor` | none | n/a | `--version` | none | hardened env |
| `launcher/src/services/fs-view.ts` probe | launch (integrity modes, frozen) | workspace | yes | `rev-parse --show-toplevel` | inherited `GIT_*` | hardened |
| `arbiter/policy/secret-history-scan.ts` (runner, line runner, blob reader) | arbiter; `scanSecretHistory`, `suggestPolicy`, `mandu doctor --secrets` | any root a caller names | yes | `rev-parse`, `config --get-regexp` (the ref storage), `rev-list [--objects]` (`--all --ignore-missing --stdin` with the reflogs' names; `--all --reflog` on a doubt), `for-each-ref`, `ls-files -s`, `cat-file --batch[-check]`, `log --raw` (trace walk, the same start) | **the lazy fetch** (a missing object read in a partial clone runs the promisor remote's transport: `core.sshCommand`, a remote helper; seen live), inherited `GIT_*`; `fsmonitor`, `showSignature` closed earlier | shared hardening, sandboxed |
| `arbiter/policy/lock-resolution.ts` `hardenedResolverGit` | arbiter background cycle, `registerRepository`, `gitHistoryLocks {roots}` | the registry: the HOME walk, launches, data-plane registrations | yes | `rev-parse`, `config --get-regexp` (the ref storage), `version`, `rev-list --no-walk` (`--all`; `--ignore-missing --stdin`; `--all --reflog` on a doubt), `for-each-ref`, `log --raw --stdin`, `ls-files -s` | as the scan | as the scan |
| `arbiter/policy/prepared-copies.ts` `prepGit`, the inventory (confidentiality-plan-14 §11.1 R3) | arbiter background, after each resolution cycle, a rotation, a launcher's report | every known repository holding a locked id: the registry | yes | `rev-parse --show-toplevel --git-common-dir --show-object-format`, `rev-parse --git-common-dir` | inherited `GIT_*` (a `rev-parse` starts nothing) | hardened, sandboxed (no writable bind) |
| `arbiter/policy/prepared-copies.ts` `prepGit`, the build (R3) | as the inventory | a private empty bare repository in the build's work directory; the repository's objects read through `GIT_ALTERNATE_OBJECT_DIRECTORIES` | no (the private repository); the source object store is the agent's | `init --bare`, `pack-objects`, `index-pack` | none: no repository, user or system config was read (`--git-dir` the private repository, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`), and the objects listed are the source index's own, so no lazy fetch | hardened, sandboxed: the build's work directory (output, empty object directory, private repository) the only writable bind; the private repository kept (defense in depth); nice 19 by `nice` around the sandbox |
| `launcher/src/git-object-twins.ts` `buildPack`'s `index-pack` (R3's crafted-pack fix, also the launch's own twins) | launcher, a pack rebuild (cache miss) | the new pack in the cache, an empty object directory, no alternates | no | `index-pack -o` | none (runs through `defaultGitRunner`); it writes the rebuilt index, so it needs a writable bind | hardened, sandboxed, the pack cache bound as for `pack-objects` |
| `arbiter/ipc/instance.ts` `gitRevOf` | arbiter start | Mandu's own checkout | yes when that checkout is an agent's workspace (developing Mandu with Mandu) | `rev-parse`, **`status --porcelain`** | `fsmonitor`, **the clean filter** (`status` re-hashes a stat-changed file), submodule recursion, inherited `GIT_*` | hardened; the dirty flag without `status` (§8.3.4) |
| the developer view's `git.ts` `gitExec` (`getCommits`, `getCommitDetail`, and `fs-view.ts`: `repoTopLevel`, `refExists`, `listTree`, `readFileAtRef`) | dashboard daemon | the shadow `repo.git` or the workspace | yes | `rev-parse`, `log`, `diff-tree -p`, `ls-tree`, `cat-file -t/-s/blob` | **`showSignature` → `gpg.program`** (`git log`), `fsmonitor` (`diff-tree` read the index), inherited `GIT_*` | hardened; `diff-tree --no-ext-diff --no-textconv` |
| `dashboard/src/self-status.ts` | dashboard, supervisor | Mandu's own checkout | as `gitRevOf` | `rev-parse --short`, `diff --name-only A B` | inherited `GIT_*` | hardened; `--no-ext-diff --no-textconv` |
| `fs-sync/src/git.ts` `gitExec`/`gitExecSync`, `fs-sync/src/ignored.ts` | fs-sync CLI and watcher (integrity modes only: frozen) | the shadow `repo.git` over the workspace; the AgentView worktree | `full`: `repo.git` is a home carve-out the agent writes; the workspace's attributes always | `status`, `add`, `commit`, `checkout`, `worktree`, `blame`, `revert`, `log`, `ls-files`, `check-ignore`, … | hooks, `fsmonitor`, commit signing, auto gc and maintenance, editor, **filter / textconv / merge drivers** | hardened (the named keys); the drivers stay open (§8.6) |
| Rust (`interceptors/`) | n/a | n/a | n/a | none | no Rust code runs git (exec-supervisor and net-supervisor only name `git` to classify it; the guard's lock backstop reads `.idx` files itself) | n/a |
| `scripts/` | n/a | Mandu's own checkout | n/a | install, update, CI, hooks | development and install only, never a user's repository | out of scope |

The agent's own git (inside its session, through the exec shims) runs
confined and is not in this table.

#### Vectors, one by one

| Vector | Which of the commands above reach it | Mitigation |
|---|---|---|
| `core.fsmonitor` | every index read: `ls-files`, `check-ignore`, `diff-tree -p`, `diff-index`, `status`, `commit` | `-c core.fsmonitor=false` |
| hooks (`.git/hooks`, `core.hooksPath`) | fs-sync's `commit`, `checkout`, `revert`; `post-index-change`, `reference-transaction`; no read command | `-c core.hooksPath=/dev/null` |
| `log.showSignature` + `gpg.program` / `gpg.ssh.program` / `gpg.x509.program` | any `git log` showing a signed commit, whatever the format | `-c log.showSignature=false` (our formats use no `%G`) |
| `commit.gpgSign`, `tag.gpgSign`, `merge.verifySignatures` | fs-sync's commits and merges | forced `false` |
| `filter.<x>.clean` / `.smudge` / `.process` (named by an attribute) | `hash-object <file>`, `add`, and every work-tree compare of a stat-changed file (`status`, `diff`, `diff-index`, `commit`'s refresh); `checkout` (smudge) | **no `-c` names an unknown driver.** No command of ours reaches one any more: §8.4, §8.3.4; fs-sync's stays open (§8.6) |
| `diff.<x>.textconv`, `diff.<x>.command`, `diff.external`, `GIT_EXTERNAL_DIFF` | a patch from porcelain `diff`, `log -p`, `show`; `blame --textconv` | none of ours makes a porcelain patch; the dashboard's `diff-tree -p` passes `--no-ext-diff --no-textconv`; the env is scrubbed |
| `merge.<x>.driver` | `merge`, `revert`, `cherry-pick` | fs-sync only: open (§8.6) |
| `core.pager`, `pager.<cmd>`, `GIT_PAGER` | output to a terminal | `--no-pager`; env scrubbed |
| `core.editor`, `sequence.editor`, `GIT_EDITOR` | a commit or revert without a message, `rebase -i` | `GIT_EDITOR=:` and `GIT_SEQUENCE_EDITOR=:` (git's own no-op) |
| `credential.helper`, `core.askPass`, `GIT_ASKPASS` | network authentication | `-c credential.helper=` (clears the list), `GIT_ASKPASS=` (empty, so git does not fall back to `core.askPass`), `GIT_TERMINAL_PROMPT=0` |
| transports: `core.sshCommand`, `GIT_SSH[_COMMAND]`, `url.<x>.insteadOf`, remote helpers, `ext::`, `remote.<x>.vcs`, `core.gitProxy`, `http.*` | `fetch`/`push`/`ls-remote`, and **the lazy fetch of a partial clone** (`extensions.partialClone`, a promisor remote): any read of a missing object (`cat-file`, `rev-list --objects`, `log`, `pack-objects`) | `-c protocol.allow=never` (every transport refused before it starts) and `GIT_NO_LAZY_FETCH=1` (git ≥ 2.44; the global `--no-lazy-fetch` is not used, an older git refuses it) |
| `core.alternateRefsCommand` | fetch and receive negotiation only | unreachable (no transport) |
| `uploadpack.packObjectsHook` | `upload-pack` only, and only from protected (system, global, command-line) config | not a vector |
| `gc.auto`, `maintenance.auto` (spawn `gc --auto` / `maintenance run --auto`, with `pre-auto-gc`) | after a commit, merge or fetch (fs-sync) | `gc.auto=0`, `maintenance.auto=false` |
| submodules (`submodule.recurse`; `status` runs git in each submodule) | `status`, `diff`, `checkout` with submodules | `submodule.recurse=false`; no `status` outside fs-sync; a child git inherits our `-c` (git passes them on in `GIT_CONFIG_PARAMETERS`) |
| `include.path`, `includeIf` | a config include is read with the including file's scope | **not a vector of its own**: `-c` outranks every file, included or not (the fixture's included `core.fsmonitor` fires under a stock git, never under ours); what `-c` cannot reach there is the same unnamed drivers |
| `core.worktree`, a `.git` file (`gitdir:`) | redirect what is read | start nothing |
| `GIT_*` in the environment (`GIT_DIR`, `GIT_CONFIG_PARAMETERS`/`_COUNT`/`_KEY_n`, `GIT_EXEC_PATH`, `GIT_EXTERNAL_DIFF`, `GIT_SSH_COMMAND`, `GIT_PAGER`, `GIT_TRACE*`, …) | every call inherited the launcher's or daemon's environment | every `GIT_*` dropped (`hardenedGitEnv`), the caller's own `GIT_DIR` etc. put back on top |
| system and global config | root-owned; `~/.gitconfig` and `~/.config/git/config` are write-guarded (`ask`, §2 above) | the system file is skipped (`GIT_CONFIG_NOSYSTEM=1`); the global file is the human's and kept (the scratch hash of §8.4 drops it too) |
| `trace2.*` | read from system and global config only | env scrubbed |
| config-based hooks (`hook.<name>.command` run on each `hook.<name>.event`; git 2.54 and later, an include's too) | the same commands as the hooks above: fs-sync's `commit` (pre-commit, prepare-commit-msg, commit-msg, post-commit, post-index-change, reference-transaction), `checkout`, `revert`; no read command (the oracle, §8.7, run under git 2.54, 2.55 and 2.56: no read springs one, even unhardened) | `core.hooksPath` does not cover them (no file in any hooks directory). `-c hook.<event>.enabled=false` for each of the 28 events githooks(5) lists (`GIT_HOOK_EVENTS`): git 2.55's switch by event, which needs no hook's name. git 2.54 has only the per-name switch: §8.6 |

### 8.3 The fix: one hardening, four copies

#### 8.3.1 The module

`hardened-git.ts` holds:

- `GIT_NO_PROGRAM_CONFIG`: `core.fsmonitor=false`, `core.hooksPath=/dev/null`,
  `log.showSignature=false`, `commit.gpgSign=false`, `tag.gpgSign=false`,
  `merge.verifySignatures=false`, `credential.helper=`,
  `protocol.allow=never`, `gc.auto=0`, `maintenance.auto=false`,
  `submodule.recurse=false`, and `hook.<event>.enabled=false` for each
  event of `GIT_HOOK_EVENTS` (the 28 githooks(5) lists; config-based
  hooks, §8.6), and, since 2026-10-21, `core.useReplaceRefs=false` and
  `advice.graftFileDeprecated=false` (history as the objects record it,
  below); `hardenedGitArgs(args, {literalPathspecs})`
  puts them, as `-c` pairs, behind `--no-pager`.
- `hardenedGitEnv(base, extra)`: `base` with every `GIT_*` removed, then
  `GIT_CONFIG_NOSYSTEM=1`, `GIT_NO_LAZY_FETCH=1`, `GIT_TERMINAL_PROMPT=0`,
  `GIT_ASKPASS=`, `GIT_EDITOR=:`, `GIT_SEQUENCE_EDITOR=:`,
  `GIT_NO_REPLACE_OBJECTS=1`, `GIT_GRAFT_FILE=/dev/null`, then `extra`.
  The last two (a security fix, 2026-10-21; confidentiality.md §7.2a "What
  the walk does not let a repository hide"): a graft or a replace ref the
  agent writes into `.git` can no longer cut commits out of a walk that
  decides what is protected.
- The sandbox (§8.5): `gitSandbox()`, `gitCommand(args, sandbox, writable)`.

No flag an older git refuses is used (a `-c` key an older git does not know
is ignored; `--no-lazy-fetch` would not be, so the environment carries it).

#### 8.3.2 Four copies, one file

The launcher, the arbiter, the dashboard and fs-sync ship standalone and do
not import each other, so the file is copied verbatim into each package's
`src/`, as `text-repack.ts` is into the two model proxies.
`tests/stack/hardened-git-parity.test.ts` fails on any drift
and runs every command form the four packages issue through each copy.
Change `launcher/src/hardened-git.ts` and copy it out. The arbiter's
runners take theirs from `secret-history-scan.ts` (`HARDENED_GIT_ARGS`,
`historyGitEnv`, `historyGitCommand`), which the lock resolver and the
prepared copies (`prepared-copies.ts` `prepGitCommand`, `prepGitEnv`)
import. The runner under the arbiter's and the launcher's git calls,
`child-run.ts` (§8.5.1), is copied the same way (arbiter and launcher) and
held byte-identical by the same test.

#### 8.3.3 Per call site

Every call in §8.2's table now goes through `hardenedGitArgs` and
`hardenedGitEnv`. Beyond that: the launcher's runner keeps literal
pathspecs, unquoted paths, no optional locks and the C locale; the
dashboard's patch is `diff-tree -p --no-ext-diff --no-textconv` and its
self-status range `diff --no-ext-diff --no-textconv --name-only`; fs-sync
keeps its own pathspec semantics (no `--literal-pathspecs`).

#### 8.3.4 `gitRevOf` without `git status`

The arbiter's start-up identity carries a dirty flag of Mandu's own
checkout. `git status` passes a stat-changed file through the clean filter
its attributes name, so the flag is now computed with no content read:
staged changes (`diff-index --cached --quiet HEAD`, index against HEAD),
untracked files (`ls-files -o --exclude-standard`), or a tracked file whose
size or mtime differs from its index entry (`ls-files --debug`, compared to
`lstat` in process: git's own first test). A file touched but unchanged now
reads dirty (git would have re-hashed it and said clean). The flag is
informational.

### 8.4 The working copy's hash

**Why it is hashed.** The object twins hide every protected version: each
one a ref, the reflog, the stash or the index names (the walk), and the
working copy's content as `git add` would store it, which may lie in the
object store as a dangling object (added once, then unstaged). The launcher
hashed it with `git hash-object -- <files>`, which applies the clean filter
the attributes name: a program the agent could plant, run at the next launch
outside the sandbox.

**What it does now** (`worktreeBlobNames`). Each present file gets two names,
both computed by git with no driver:

1. its raw bytes, `hash-object --no-filters`: what `git add` stores when no
   conversion applies;
2. its bytes as git converts them WITHOUT a driver (end of line, `ident`,
   `working-tree-encoding`): hashed in a **scratch git directory**, a
   temporary directory holding only `HEAD`, `objects/`, `refs/`, the
   repository's `info/attributes` and a config with the object format, with
   `GIT_WORK_TREE` the repository's and `GIT_CONFIG_GLOBAL=/dev/null`. The
   repository's effective `core.autocrlf`, `core.eol` and
   `core.attributesFile` (read by one hardened `git config --get-regexp`;
   `--path` is asked again only for a value git would expand) are passed as
   `-c`. Every attribute applies as it would for `git add`, but no config
   names a driver for one, so none runs, whatever the attributes say.

Both names are hidden; a name no object carries costs nothing. The unit
test checks, for SHA-1 and SHA-256 repositories, that the names include what
a stock `git add` stores for a CRLF file under `text eol=lf` and a file
under `ident`, and that the planted clean filter never ran.

**What this gives up, and why that is acceptable.** A file a real clean
driver transforms (git-lfs, git-crypt, nbstripout) is stored as the
driver's OUTPUT, which only the program can compute. That version is still
hidden whenever a ref, the reflog, the stash or the index names it (the
walk and the index read); only a DANGLING copy of it (added, then unstaged,
never committed) is no longer found. For git-lfs and git-crypt that output
is a pointer or ciphertext, not the secret. And inside a confined session
the agent cannot make such a blob of a protected file at all: it reads the
twin, so whatever it adds holds the symbol, not the secret. The blob of the
real bytes can only come from the human's own `git add`, outside the
session; if the agent planted the filter, that `git add` already ran the
agent's program as the human (§8.3's residual above).

### 8.5 Defense in depth: the git sandbox

Where an unprivileged bubblewrap works, the launcher's runner
(`defaultGitRunner`) and the arbiter's runners (the scan's runner, line
runner and blob reader, the lock resolver's, and the prepared copies'
`prepGit`) run git inside a sandbox (`gitCommand`): `--unshare-user --unshare-pid --unshare-net
--unshare-ipc --unshare-uts --die-with-parent --new-session --cap-drop ALL
--disable-userns`, `--ro-bind / /`, a fresh `/dev` with the host's
`/dev/shm` read-only on it, `/proc`; read-write only where the call must
write: the launcher's `buildPack` binds its pack cache (for `pack-objects`
and for `index-pack`, which writes the rebuilt index beside the pack); the
arbiter's R3 build binds only its own work directory in the cache
(`.tmp-<key>-<pid>-prep/`, holding the output, the empty object directory
and the private bare repository: one bind, since `pack-objects` renames
its temporary pack from the object directory into the output and a rename
across two bind mounts fails `EXDEV`), so a program started there cannot
touch another sealed copy. A low-priority call (R3's build) runs as
`nice -n 19 <bwrap …>`: renicing the child after the spawn would race
bubblewrap's own fork. No network, no capability, no write
outside that directory. `probeGitSandbox` runs `git --version` inside with
Mandu's own root-owned bubblewrap (`/usr/lib/mandu/bin/bwrap`, `mandu
setup`) and then the distribution's (`bwrap-path.ts`: an administrator's
`bwrap_path`, else the first on PATH outside the current directory, by
absolute path, never a bare `bwrap`;
rootless-confinement-ubuntu-2404.md §0.7), each with the flag set above and then
without `--disable-userns` (bubblewrap before 0.8); the first that works is
used for the process's lifetime. None works (no bwrap, no unprivileged user
namespace, an AppArmor restriction without Mandu's grant): the
hardened git runs as is. `MANDU_GIT_SANDBOX=0` turns it off. This follows
[privilege-model.md](./privilege-model.md) §0: an unprivileged primitive, on by default where the
kernel allows, self-disabling where it does not.

**Where it is off, it says so.** `mandu doctor` runs the same probe and
reports it under "What Mandu enforces on this machine": ✓ with the
bubblewrap it runs, · when `MANDU_GIT_SANDBOX=0`, and ✗ with the fix when no
bubblewrap can start one (an unprivileged hardening left unused is a gap,
privilege-model.md §0). A bubblewrap inside another one is the other case:
on a host with Ubuntu's `bwrap-userns-restrict` the probe fails inside any
bwrap sandbox built by `/usr/bin/bwrap`, which is how the git sandbox is off
in a local `scripts/ci/ns-run.sh` run and its tests SKIP there;
continuous-integration.md §5.6 has what ns-run prints and how Mandu's own
bubblewrap closes it.

**Cost.** Measured: `git --version` takes
3.9 ms plain and 21 ms sandboxed, so about 17 ms a call. A launch's object
twins make about ten calls a repository, concurrently across repositories,
now all in one sandbox per launch (§8.5.3); the arbiter's background resolver cycle with
nothing new (about six calls a repository, two at once) grows by about 50
ms a repository, off every request's path.

**What it adds.** Should a program start anyway (a vector not known today,
a git upgrade that adds one), it cannot plant anything on disk (a shell
startup file, a hook in another repository, a systemd unit), cannot reach
the network, and holds no capability. `launcher/test/kernel/git-sandbox.test.ts`
runs a filter on purpose inside it and checks each.

**What it does not.** The program can still READ what the user can
(including secrets) and write to git's stdout, which the caller parses, and
to the directory its call binds (the launcher's pack cache under
`pack-objects` and `index-pack`, an R3 build's own work directory); in the
launcher's git session (§8.5.3) it can still kill the session's other calls
(they fail closed), and no more (an empty `/proc`, Yama). It is a backstop behind
§8.3 and §8.4, not a replacement. Not applied (hardening only): the dashboard's
and fs-sync's git, and the launcher's single probes (`rev-parse`, `config
--get-regexp`, `--version`), each a read §8.2 shows runs nothing; wrapping
them would add a bubblewrap start to latency-sensitive paths for no known
vector. **Next steps:** Landlock (`mandu-landlock-apply`) and a seccomp deny
filter inside the git sandbox, to narrow reads to the repository and the
git installation; the sandbox for the dashboard's readers.

#### 8.5.1 Every call settles

Moving the R3 build into the sandbox made CI hang (a component suite at its
900 s limit, a sandbox test at its 300 s timeout). The cause is in how a
sandboxed call is killed, not in git:

- node reports a child's end on `close`, which waits for EVERY holder of
  its stdout and stderr, not for the child itself;
- bubblewrap's sandbox child, just cloned into its namespaces, blocks
  reading an eventfd until its parent has set it up, and binds its life to
  that parent (`--die-with-parent`) only later;
- a runner that kills only its direct child (`child.kill("SIGKILL")`: `nice`,
  which is bubblewrap after its exec) in that window (the preparer's or the
  resolver's `stop()` while a background cycle is starting a call; a
  deadline on a starved host) leaves the sandbox child reparented to init,
  blocked on that read forever, holding the pipes. `close` never fires, the
  call never settles, the cycle never ends, and `ArbiterServer.close()`
  awaits `stop()` forever. `nice -n 19` on a loaded host widens the window.

Measured: about 3% of SIGKILLs of `nice -n 19 bwrap … git --version` within
8 ms of the spawn left such an orphan, and an `ArbiterServer` closed right
after `registerRepository` hung in about 1 close in 60.

**The fix: `arbiter/src/child-run.ts` `runChild`**, the one runner under the
arbiter's async git calls (the preparer's `prepGit`, the resolver's
`hardenedResolverGit`, the scan's `defaultHistoryGitRunner`,
`defaultHistoryGitLines` and `defaultBlobReader`):

- the child runs in a process group of its own (`detached`), and every kill
  is SIGKILL to the WHOLE group: `nice`, bubblewrap, and bubblewrap's
  sandbox child, which calls `setsid` (`--new-session`) only after that
  eventfd read, so the orphan above is always still in the group (none left
  in hundreds of runs);
- and to every descendant the runner reads just before the kill
  (`descendants`: `/proc/<pid>/task/<tid>/children`, Linux; none where
  there is no `/proc`, as on macOS, whose Seatbelt sandbox execs git in
  place). The second window (found 2026-10-21, CI jobs 18255 to 18296):
  after that setsid the sandbox child, the sandbox's pid 1, leads a session
  of its own, out of the group kill's reach, and arms `--die-with-parent`
  only in its init loop, after it forked the command, with no check that
  bubblewrap is still alive. A kill between the two left the sandbox running
  the command to its natural end, bound to nothing, holding the pipes: 2 of
  8192 kills within 3 ms of the spawn on an idle host left a `sleep 3`
  sandbox running its 3 s, and once the CI guest's suites shared one cpu
  cgroup (continuous-integration.md §11: nice 19 then weighs against every
  other suite) a starved `git --version` sandbox held the output past the
  test's 5 s grace in 10 of 22 runs. In
  production that is a killed call (a deadline, a `stop()`) whose git runs
  on to its end, a build's `pack-objects` included, and costs the kill
  grace. Killing the sandbox's pid 1 ends its PID namespace, the command
  with it. Each descendant is read while its parent lives, so it has not
  been reaped nor its pid reused at the read, and only microseconds pass
  between the read and the kill. Not read once node has reaped the child
  (its exit reported): its pid may be another process's by then;
- a killed call settles within a second whatever still holds its pipes
  (they are destroyed); an exit whose output does not close within ten
  seconds (a process it started, outside the group, holds it) settles as a
  FAILURE after SIGKILL to the group: its output may be incomplete. So a call
  settles by its deadline plus a second at the latest;
- output over a call's cap kills it and fails it (the scan's former
  `maxBuffer`; the preparer's 1 MiB), never a silently truncated answer;
- the preparer adds its own bound on top, whatever runner it is given
  (`PreparedCopies.call`): a call that has not settled by its deadline plus
  `settleGraceMs` (5 s) is given up as a failure and logged, and `stop()`
  settles every call in flight at once; neither the preparer nor the
  resolver starts a call once stopped.

Fail closed: a call given up on is a failed call. The repository is
`failed` for that cycle and stays with the backstop (confidentiality.md
§7.2a, R4); nothing is sealed or served from it, and the next cycle tries
again.

**The launcher, the same runner.** The launcher's `defaultGitRunner`
(launch prep, `git-object-twins.ts`) runs through `runChild` too,
`launcher/src/child-run.ts`, a verbatim copy of the arbiter's (the packages
share no code; the parity test of §8.3.2 holds the two byte-identical).
`execFile`'s deadline kill (SIGTERM) reaches only bubblewrap, so a deadline
landing in bubblewrap's start-up on a starved host left sandbox children
behind. Kept from `execFile`: the 120 s default deadline, a 512 MiB cap on the output (execFile's
`maxBuffer`, `GIT_RUNNER_MAX_STDOUT`; over it the call fails, it is never
silently truncated), a failed or killed call is code 1 and the caller
refuses the launch unless `--best-effort` (a `GitObjectTwinError`). New:
stderr is kept to 64 KiB (the callers quote its last line), and
an exit whose output a process outside the group keeps open fails after
the ten-second close grace instead of waiting for that process.

#### 8.5.2 macOS: the Seatbelt git sandbox (2026-09-30)

Until this section, `probeGitSandbox` returned null off Linux, so on macOS
every hardened call above ran with the config and environment hardening
only, among them the arbiter's background lock resolver over every
repository its home walk finds (it has no platform gate). The daemon's R3
preparer has been Linux only since 2026-09-30 (`preparedCopiesOff`): on
macOS it runs only for an embedder or a test that names a cache. macOS
has no namespaces, but an unprivileged process can run a program under a
Seatbelt profile the kernel enforces (`sandbox-exec`, the primitive the
whole-agent profile of confidentiality.md §7.3 uses). The non-root
principle (privilege-model.md §0) makes that a gap to close, so the sandbox
has a second kind.

**Where Mandu's git runs.** Outside the agent's profile: that profile wraps
only the agent's argv (the launch prefix), the launcher's own git
(`trackedSecretRepos`, `lockedHistoryRepos`, the probes) runs in the
launcher process before the wrap is applied, and the arbiter, the dashboard
and fs-sync are daemons
started before it. So the git sandbox is a profile of its own, never nested
in the agent's. The one exception is a `mandu …` command the agent itself
runs (`mandu doctor --secrets`, `mandu revert`, a nested launch): its git
runs inside the agent's profile, where no second profile can be applied
(below) and the outer one confines it.

**The profile** (`gitSeatbeltProfile(git, writable, canonical)`, rendered
per call and passed inline with `-p`: no profile file, so nothing to write
protect, race or clean up; the argv carries only paths). SBPL is last match
wins: `(allow default)`, then each deny, then its own exception.

```
(version 1)
(allow default)
(deny process-fork)
(deny process-exec)
(allow process-exec (literal "<git, resolved>"))
(deny file-write*)
(allow file-write* (literal "/dev/null") (subpath "<writable, as given>") (subpath "<writable, canonical>") …)
(deny file-read* file-write* (literal "/dev/tty") (regex #"^/dev/ttys[0-9]+$"))
(deny network*)
(deny mach-lookup)
(allow mach-lookup (global-name "com.apple.system.opendirectoryd.libinfo"))
(deny appleevent-send)
(deny signal)
(allow signal (target same-sandbox))
(deny ipc-posix-shm*)
(deny ipc-posix-sem* ipc-sysv*)
(deny iokit-open)
```

The command is `{file: "/usr/bin/sandbox-exec", args: ["-p", profile,
<git>, …hardened args]}`, both by absolute path; `/usr/bin/nice -n 19` wraps
it for R3's build as on Linux.

| bubblewrap (Linux) | Seatbelt (macOS) | Measured on macOS 26.5.1 (2026-09-30) |
|---|---|---|
| `--unshare-net` | `(deny network*)` | TCP to 127.0.0.1 and to a public address: EPERM; a Unix socket (`/var/run/mDNSResponder`, a test server): EPERM, the server saw no connection |
| `--ro-bind / /` plus `--bind <w>` | `(deny file-write*)`, then `/dev/null` and each writable path | a write outside or into the repository: EPERM; the bound directory writable; `pack-objects`, `index-pack` (writes `.idx` and `.rev`) and `init --bare` succeed in the bound cache; `pack-objects`' rename from the object directory into the output works (no mounts, so no EXDEV) |
| `--new-session` | the `/dev/tty` and `/dev/ttys*` deny | opening the terminal: EPERM (the launcher's calls share the human's session) |
| `--unshare-pid` | `(deny signal)` then `(allow signal (target same-sandbox))` | a signal to an outside pid: EPERM; to itself: delivered. (`(deny signal (target others))` did NOT work) |
| `--unshare-ipc` | `(deny ipc-posix-shm*)`, `(deny ipc-posix-sem* ipc-sysv*)` | with the shm deny alone, `shm_open` was refused but `sem_open`, and System V shared memory, semaphores and message queues another process made (reached by key or by id: `shmget`/`shmat`, `semget`/`semop`, `msgget`/`msgsnd`), were allowed; with both, each is EPERM. Creating a new private System V object (`IPC_PRIVATE`) stays allowed: it reaches no other process |
| (host services) | `(deny mach-lookup)` but the user database; `(deny appleevent-send)` | |
| `--cap-drop ALL`, `--disable-userns`, `--unshare-user` | none needed: no user namespaces or capabilities exist; a setuid exec is refused inside a profile anyway (`/bin/ps`: EPERM) | |
| (none: a program starts and is contained) | **`(deny process-fork)`, and no exec but git** | with STOCK git (none of the hardening) over the hostile fixture, the markers directory writable: 0 of the traps fire across `status`, `log -p`, `log %G?`, `diff`, `diff-tree -p`, `hash-object`, `ls-files`, `cat-file`, `fetch`, `ls-remote`; with the repository writable, `commit`, `add` and `checkout` too. git says `cannot fork() for …: Operation not permitted`; a REQUIRED filter then fails the call (exit 128), fail closed |

So macOS goes BEYOND bubblewrap here: a program a repository names cannot
start at all, where bubblewrap lets it start and contains it. Every hardened
form Mandu issues passes under the full profile (the parity test's forms,
`pack-objects`, `index-pack`, `init --bare`, the `worktreeBlobNames` scratch
hash with its git directory under `/var/folders`).

SBPL facts it rests on, each measured:

- **Path rules match the resolved path only.** A subpath spelled `/tmp/…`
  was denied and `/private/tmp/…` allowed; node's `tmpdir()` is
  `/var/folders/…`, a link too. So each writable path is emitted as given
  AND canonical (`canonicalSpelling`: the realpath of its longest existing
  prefix, the launcher's `seatbelt-profile.ts` `canonicalPath`, copied); a
  relative path, one holding `..` (the kernel resolves it through links, so
  no lexical spelling names what it names) and `/` are dropped, so the write
  fails (fail closed). Without the canonical spelling `pack-objects` failed
  on every cache under `tmpdir()`.
- **An exec rule matches the resolved path only**: allowing a link's own
  path failed. A `#!` interpreter is exec-checked too.
- **`(deny mach-lookup)` alone breaks `~user/` paths**: git dies "could not
  expand include path '~u/…'" because `getpwnam` asks opendirectoryd; the
  one lookup allowed back is `com.apple.system.opendirectoryd.libinfo`.
- **`sandbox-exec` does not nest.** Under any outer profile but a bare
  `(allow default)` (a single deny of file-read, network, process-exec or
  appleevent was enough) an inner `sandbox-exec` exits 71, `sandbox_apply:
  Operation not permitted`.
- **`sandbox-exec` execs in place** (the same pid): no orphan window (§8.5.1).

**The git it runs** (`resolveGitBinary`, at probe time): the first
executable `git` on PATH (absolute entries only), resolved; then, when that
git's `--exec-path` names a directory whose `git` resolves to an executable
file, that one. The Apple `/usr/bin/git` is a shim that finds the developer
directory's git through xcrun (a second exec the profile would refuse, and
xcrun's own cache writes; `DEVELOPER_DIR=/nonexistent` breaks it); the
Command Line Tools' `libexec/git-core/git` → `../../bin/git` is the real
binary. `--exec-path` reads no repository. It runs SANDBOXED: under the git
profile itself with nothing writable (`sandbox-exec -p <profile for that
binary> <it> --exec-path`: no network, no write but `/dev/null`, no fork,
no exec but that one binary), so a `git` planted first on PATH never runs
outside a sandbox in the probe (a `#!` script cannot even start its
interpreter there; a planted binary answers inside it). Only the Apple shim
(`/usr/bin/git`, whose exec of xcrun's pick the profile refuses: measured
exit 71) is asked again as is when that run fails, and only while it and
every directory above it are root-owned and not group- or other-writable;
never another binary a link on PATH names, root's or not (the agent can
point a link in `/opt/homebrew/bin` at any system binary). A root-owned
shim does NOT mean root chose what it runs: it runs the binary xcrun's
per-user cache names, `$(getconf DARWIN_USER_TEMP_DIR)xcrun_db`, a file
the user owns and the agent could rewrite under its profile. A poisoned
cache would have had that as-is run start a program of the agent's outside
every sandbox and hand back an exec path of its choosing (whose `git` the
sandboxed runners would then run, contained), and every other call that
runs the shim would have started that program too (§2's vectors). So since
2026-09-30 every hardened call carries `xcrun_nocache=1` (`hardenedGitEnv`, §3.1):
xcrun ignores the cache and finds git through the developer directory
`xcode-select` chose, a setting only root can change (measured on macOS
26.5: a poisoned cache is ignored). And the agent's profile write-denies
the cache as a file that runs later (write-protection.md §9; measured: git
still works with the cache write-denied, and a rename over it is refused).
`gitSandbox()` probes again when the git it
holds is gone (a `brew upgrade` moves Homebrew's Cellar path).

**Integrated probe contract.** A successful sandboxed `git --version`
probe may return `gitVersion` on both Linux and macOS, avoiding another
version subprocess. A transient probe result is never successful: it is
retried after one second, doubling to at most 300 seconds. If a resolved
Seatbelt git disappears (for example after a Homebrew upgrade), the previous
sandbox remains the fail-closed answer until reprobe succeeds. The launcher's
per-boot disk probe cache persists only Linux bubblewrap passes; it does not
persist Seatbelt profiles or SDK-dependent resolved macOS git paths.

**The probe** (`probeGitSandbox`, platform `darwin`): `MANDU_GIT_SANDBOX=0`
→ none; `/usr/bin/sandbox-exec` not an executable file (never a PATH
lookup, as for the whole-agent wrap) → none; no git → none; else `sandbox-exec
-p <the read profile> <git> --version`, and anything but exit 0 → none:
exit 71 inside another profile (or when the profile refuses the binary: the
shim without the Command Line Tools, a planted `#!` script), a future macOS
that drops `sandbox-exec`. None means the hardened git runs as is, exactly
as before. A run that could not be judged (a timeout, no free process) is
not a final none, and a process that once had a Seatbelt sandbox never
falls back to none (§8.5, the per-process answer).

`mandu doctor` (a fresh probe, §8.5) tells the macOS "none" reasons apart
from facts it establishes: no `/usr/bin/sandbox-exec`; inside another
profile (`sandbox-exec -p "(version 1)(allow default)" /usr/bin/true` exits
71 only there); no git on PATH; the resolved git still the `/usr/bin/git`
shim (its `--exec-path` named none: no Command Line Tools, with
`xcode-select --install` as the fix); a probe that could not finish; else
the resolved git did not run under the profile. Inside another profile and
an unfinished probe are a ·, the rest a ✗. It never claims nesting it has
not seen, nor in the row that an outer profile confines git.

**Cost.** Measured on the dev Mac (2026-09-30, arm64): `git --version` takes
2.0 ms running the Command Line Tools binary directly, 6.6 ms sandboxed, and
5.2 ms through the `/usr/bin/git` shim Mandu ran before: about 1.5 ms a call
over the old path (bubblewrap: about 17 ms).

**Residuals** (beyond §8.6's):

- **Reads stay open**, as on Linux: git, and a program should one start,
  can read what the user can, and git's stdout is trusted by the caller.
- **The process list stays visible** (`(allow process-info* (target
  self))` did not hide other processes from `pgrep`); moot while only git
  can run.
- **No die-with-parent**: not needed, one process and no fork.
- **The git binary is whatever PATH names.** The Homebrew prefix and
  `~/.local/bin` are writable by the agent (guarantees.md §3), and a `git`
  planted there still runs OUTSIDE every sandbox at each call that is not
  sandboxed, on both platforms: the launcher's single probes
  (`readGitRemotes` on every launch with the net guard, the fs-view and
  `mandu revert` probes, the doctor's `--version`), `gitRevOf` /
  `arbiterRevOf`, the dashboard and fs-sync; and at every call, sandboxed
  runners included, wherever the probe found no sandbox (a planted `#!`
  script is itself such a case: the profile cannot start its interpreter,
  so the probe says none). The probe's `--exec-path` runs under the git
  profile (above) for every binary but the root-owned Apple shim, which it
  runs as is; that run, like every call through the shim, ignores xcrun's
  per-user cache (`xcrun_nocache=1`, above), so it starts the git
  `xcode-select` chose, not one the agent named there. Where the sandbox
  holds, only the resolved binary runs inside it (a planted binary, then,
  runs contained: no write outside the binds, no network, no other
  program). Its stdout is trusted by the caller either way. Phase 2's
  root-owned git would close the sandboxed runners' part.
- **The user's own git reads xcrun's cache too.** A `git` typed in a
  terminal (Apple's shim, no `xcrun_nocache`) runs what
  `$(getconf DARWIN_USER_TEMP_DIR)xcrun_db` names, as do the other xcrun
  shims in `/usr/bin`. Mandu now refuses the agent's writes to that file
  under its profile (write-protection.md §9); a write made where no profile
  applies (mode `off`, `MANDU_WRITE_PROTECT=0`, or before Mandu) is not
  undone.
- **`sandbox-exec` is deprecated** by Apple; the probe handles its absence.
- **Inside another profile** (a `mandu` command the agent runs): no git
  sandbox; the outer profile governs.
- **Unsandboxed calls** (the launcher's single probes, `gitRevOf` /
  `arbiterRevOf`, the dashboard, fs-sync) stay unsandboxed on both
  platforms (§8.5).

**Phase 2** (recommended by the non-root principle, not built):
`(deny file-read* (subpath <state-root>) (subpath <events>) (subpath
<human-plane dirs>))` in the git profile (no git call reads them, and a
hostile `objects/info/alternates` or `include.path` pointing there would
then fail); the ~5 ms sandbox for the dashboard's readers and the
launcher's probes; fs-sync's git with fork and exec denied, which closes
§8.6's driver residual on macOS; and preferring a root-owned git (the Command
Line Tools or Xcode, root-owned ancestors, like `MANDU_OWN_BWRAP`).

#### 8.5.3 One sandbox for a launch's reads (2026-10-16)

One bubblewrap per call cost the launch's history step most of its time:
about 17 ms of namespace set-up a call, serialized in the kernel (eight
calls at once took 70 ms a batch sandboxed, 12 ms plain), and a launch makes
30-70 of them (the step, its prefetch, the placeholder watch). So the
launcher opens one **git session** per launch (`launcher/src/git-session.ts`
`GitSession`; `run.ts` opens it beside the prefetch, warms it, and closes it
with the prefetch on every path, right after the secret setup):

- **One sandbox, the same one.** The session starts ONE bubblewrap with the
  probe's flags (`sessionRunnerCommand`: `gitCommand`'s flags, nothing bound
  read-write, but an empty read-only `/proc`: "Keeping the calls apart"
  below) running a request runner
  (`GIT_SESSION_RUNNER_SOURCE`, `node -e`, this process's own node, an empty
  environment). The runner starts each call's git INSIDE that sandbox, as
  many at once as the callers ask. It starts only `git` (fixed in its
  source); a request carries the argv (an array: no shell), the cwd, the
  call's full environment (the same `hardenedGitEnv` the per-call runner
  passed bubblewrap, which passes it through unchanged) and its stdin. The
  answer is the raw bytes, framed, decoded by the launcher as `runChild`
  decoded them: the same strings, the same exit codes (a death by signal is
  128 + the signal, as bubblewrap reports its command's), the same stderr
  cap. Unit and kernel tests hold the answers byte-identical to the
  per-call runner's.
- **Every call still settles (§8.5.1).** The call's git is a process group
  of its own inside the sandbox; its deadline (or its output passing the
  cap, or an owner's kill: the prefetch's `close`) SIGKILLs the group, and
  the call fails (code 1). When a git exits, whatever it left in its group
  is killed (the per-call sandbox's pid namespace died with its command).
- **Fail closed.** The runner ending under calls in flight (a crash, a
  kill, an unreadable or early frame, its sandbox gone) fails every one of
  them: the step refuses the launch as for any failed git call (unless
  `--best-effort`). A kill that does not settle its call within the kill
  grace, or an exit whose output a process outside its group keeps open past
  the close grace, fails the call AND tears the whole sandbox down (so that
  process dies, as it did with its call's own sandbox). After that, the
  session's calls run one sandbox each. A runner that ends before it said it
  is ready ran no call: its calls, and the later ones, run one sandbox each
  (a host where node cannot start in the sandbox loses the speed, never a
  call or a confinement).
- **Not in a session**, one sandbox each as before: a call that writes (the
  pack build's `--bind` of the cache is per call), and every call where the
  sandbox is not bubblewrap: none (`MANDU_GIT_SANDBOX=0`, no bubblewrap) or
  Seatbelt (§8.5.2: its profile denies fork, so no runner can start git).
  The arbiter's runners, `mandu doctor`, `revert` and the single probes are
  unchanged.
- **Lifetime.** `close()` SIGKILLs the session's process group (bubblewrap,
  and with `--die-with-parent` its sandbox and every git in it), fails what
  is in flight and refuses later calls. An idle session holds no reference
  on the event loop, and a process `exit` kills it.

**Keeping the calls apart.** The calls of one session share a pid
namespace, which one sandbox per call did not. A program that started in
one call despite §8.3 and §8.4 (no vector known) could already write its own
call's output (§8.5, "What it does not"), so it could make its own
repository mask less; it must not reach ANOTHER call, on another repository
of the launch. Two rules close that:

- **An empty, read-only /proc.** The session sandbox mounts an empty tmpfs
  on `/proc`, remounted read-only (`--tmpfs /proc --remount-ro /proc` in
  place of the probe's `--proc /proc`; `sessionSandboxFlags`). No call can
  open another's `/proc/<pid>/fd` (its pipes), `environ` or `mem`, nor list
  the pids. Never no mount at all: under `--ro-bind / /` the host's `/proc`
  would show through the recursive bind. git and the runner need no `/proc`
  (the stray-process rules use process groups). A git call holds only its
  own stdin, stdout and stderr (node opens every other descriptor
  close-on-exec). The per-call sandbox keeps its procfs.
- **Only under Yama.** A session is used only where the host's
  `kernel.yama.ptrace_scope` is 1 or more (`sessionAllowed`, read before the
  session opens): ptrace, `pidfd_getfd` and `process_vm_writev` need
  PTRACE_MODE_ATTACH, which Yama then refuses for anything but a
  descendant, so no call can attach to a sibling or to the runner. Scope 0,
  no Yama, or an unreadable value: one sandbox per call, as before (fail
  toward isolation). `mandu doctor` already warns at scope 0.

**What remains, and why it is acceptable.** A program can still `kill()` a
sibling call by a guessed pid (one uid in one user namespace). That call
fails, the step refuses the launch (or, under `--best-effort`, leaves that
repository named and unmasked, as for any failure): fail closed, and only
after the hardening itself has failed. The shared network and IPC
namespaces hold nothing a git call listens on or uses. What the sandbox
keeps from the host is unchanged (no write but the call's binds, no
network, no capability, no host process).

**Cost.** On the dev host (load average 30-120), the step over four
repositories in `$HOME` (30 calls, warm caches): 270 ms with a sandbox per
call, 140 ms in a warmed session; 30 cheap calls eight at a time: 265 ms
with a sandbox each, 96 ms in a session, 149 ms with no sandbox (the runner forks git
faster than the launcher's large process). The runner's own start (about
130 ms there) is hidden by the launch's warm-up; a step that opens its own
session (no launch passed one) pays it.


### 8.6 Still open

- **fs-sync's drivers (frozen axis).** In `full` mode the agent can write the
  shadow `repo.git` (a home carve-out, on-disk-layout.md §4), and fs-sync's
  `add`, `status`, `checkout`, `worktree add`, `revert` and `blame` run the
  filter, merge and textconv drivers its config names; no `-c` switches off
  a driver by an unknown name. The named keys (§8.3.1) are closed. Recorded in
  protection-modes.md §10.7; a revival of the axis must close it (a driver-free
  config for the substrate, e.g. the scratch-directory approach of §8.4, or
  running fs-sync's git in the sandbox of §8.5 with the substrate writable).
- **A dangling copy of a driver's output** (§8.4).
- **Config-based hooks: closed from git 2.55, open on git 2.54 for fs-sync
  alone (2026-10-17).** git 2.54 (its release notes: "Hook commands are now
  allowed to be defined ... in the configuration files") runs
  `hook.<name>.command` on each `hook.<name>.event`, with no file in any
  hooks directory, so `core.hooksPath=/dev/null` does not stop it. Measured
  with git built from the kernel.org tarballs: 2.53 (the dev host's) runs
  none; 2.54, 2.55 and 2.56 run them, and under `-c core.hooksPath=/dev/null`
  too; `-c hook.<name>.enabled=false` stops one on all three; `-c
  hook.<event>.enabled=false` (every hook of an event, whatever its name)
  stops them on 2.55 and 2.56 and is ignored by 2.54. The forced config now
  carries that switch for every event githooks(5) lists (§8.3.1), which an
  older git ignores. **What stays open:** on git 2.54 exactly, no `-c` can
  name a hook the repository chose the name of, so a command that runs
  hooks still runs them there. No read command of ours runs a hook (the
  oracle over the fixture's config hooks, run under 2.54, 2.55 and 2.56);
  fs-sync's `commit`, `checkout` and `revert` (frozen axis) do, outside any
  sandbox. Closing it there would mean reading the hook names first
  (`config --get-regexp '^hook\.'`, then one `hook.<name>.enabled=false`
  each), racing an agent that writes the config in between; with the axis
  frozen it is recorded instead (protection-modes.md §10.7). A future git
  whose new hook event is not in the list: the sandbox where it runs (§8.5)
  and the next item.
- **New keys in future git.** A new program-starting key is caught by the
  sandbox where it runs (§8.5), and must be added to the forced config and to
  the fixture (`tests/lib/hostile-git-repo.ts`).
- **The human's own git** on the workspace (§3 above).
- **Global config.** The user's `~/.gitconfig` is trusted (write-guarded,
  `ask`); a human who approves an agent's write to it trusts what it names.

### 8.7 Tests

- `launcher/test/unit/hardened-git.test.ts`: the forced config (every hook
  event of githooks(5) switched off by event, only `hook.<event>.enabled`
  keys, taken by the host's git without a warning; a commit in a repository
  whose config names a hook for every event: a stock commit runs them exactly
  from git 2.54 on, the hardened one runs none on 2.55 and later), the scrubbed
  environment, the sandbox's command line and flag sets, the probe (injected),
  `eolConfigArgs` / `scratchGitConfig`, `worktreeBlobNames` against a stock
  `git add` for SHA-1 and SHA-256 with a planted clean filter that never runs;
  the pack rebuild's writers (`pack-objects`, `index-pack`) bind the pack
  cache and no other call binds anything.
- `arbiter/test/unit/prepared-copies.test.ts` (R3's runner):
  `prepGitCommand` (the hardened options before the call's own, the sandbox
  with only the given binds, `nice` around it), `prepGitEnv` (no inherited
  `GIT_*`), and a cycle's recorded calls: the `rev-parse`s bind nothing;
  `init`, `pack-objects` and `index-pack` bind only the build's work
  directory, run in the cache against the private repository inside it,
  with no user config, at nice 19; no caller repeats the hardening. And
  §8.5.1: a call that never settles is given up at its deadline plus the
  grace (the repository failed, logged, nothing sealed, built on the next
  cycle; the build case drives the deadline with node's mocked `setTimeout`,
  so the stalled call is given up exactly at its deadline plus the grace and
  not a tick before, and the retry's real git has no deadline a loaded host
  can trip), `stop()` during such a call returns at once and no call starts
  after it, and `stop()` racing a cycle's real (sandboxed) git returns every
  time. `arbiter/test/unit/lock-resolution.test.ts`: the same race for the
  resolver.
- `arbiter/test/unit/child-run.test.ts` (§8.5.1): exit codes, output, input;
  the deadline kills the whole process group (a background process dies
  too); a descendant that left the group (setsid) dies with the kill; a
  straggler that is neither in the group nor a descendant costs the grace
  and fails the call; `descendants` lists a tree parents first;
  an owner's kill; the output cap; a program that cannot start; and,
  where the git sandbox works, 256 kills of `nice -n 19 bwrap … git` in
  its start-up with no output left to the grace (without the group kill
  this fails), and 512 such kills of a sandbox that would run `sleep 300`,
  so a sandbox that outlives the kill holds the output on any host (without
  the descendant kill this fails: 3 of 512 on an idle host). Their kill
  grace is 120 s, since at nice 19 on a CPU-bound host killed processes
  can wait a minute to exit (continuous-integration.md §11).
- `arbiter/test/component/prepared-copies.test.ts` (§8.5.1): a real
  `ArbiterServer` closed right after `registerRepository`, twelve times,
  each close returns.
- `launcher/test/unit/fs-view.test.ts`: the fs-view probe's arguments and
  environment.
- `launcher/test/unit/doctor.test.ts` (§8.5, doctor's row): each state's
  wording (on names its bubblewrap, off, unavailable with its fix), the probe
  handed doctor's environment, Linux only, no row without a probe;
  `launcher/test/component/doctor-git-sandbox.test.ts`: `mandu doctor` through the
  real CLI agrees with the host's probe, and `MANDU_GIT_SANDBOX=0` reads
  "turned off".
- `scripts/test/ci-ns-run.test.sh` (`sandbox` kind): whether a bubblewrap nests
  in ns-run's sandbox, and the note a box that cannot nest prints
  (continuous-integration.md §5.6).
- `arbiter/test/unit/git-hardening.test.ts`: `HARDENED_GIT_ARGS`,
  `historyGitEnv`, the scan's and the resolver's runners over a hostile
  repository, `gitRevOf` (clean, edited, hostile), `parseLsFilesDebug`,
  `statDiffers`.
- `dashboard/test/unit/git-hardening.test.ts`, `fs-sync/test/unit/git-hardening.test.ts`:
  each package's readers (and fs-sync's commit) over a hostile repository.
- `tests/stack/git-hardening.test.ts` (the oracle, `secrets`):
  a hostile repository where every key and attribute of §8.2 names a marker
  (`tests/lib/hostile-git-repo.ts`), a stock git as the control (it springs
  them), and every call path through production code: the launch prep
  (`prepareGitObjectTwins`, loose and packed), the net guard's remotes,
  `mandu revert`'s probe; the arbiter's `registerRepository`,
  `gitHistoryLocks {roots}`, `scanSecretHistory` and `suggestPolicy` through
  the real data socket, and `gitRevOf`; R3's prepared copies (the hostile
  repository packed, a label locking its deleted key, one preparation cycle
  through a real ArbiterServer: the copy holds every other object of the
  pack, each file sealed with its bytes, git over it reads the history but
  not the locked version); the dashboard's readers and
  self-status; fs-sync's runner and ignore check; a partial clone with a
  missing blob (no lazy fetch). No marker fires. With the hardening removed,
  the same file fails on `fsmonitor`, `gpg` and `ssh` markers. (The R3
  case stays quiet even then: its commands, `rev-parse` and the build in a
  private repository, reach no key §8.2 lists; the case holds that as the
  preparer changes.)
- `tests/stack/hardened-git-parity.test.ts`: the four copies
  byte-identical, and the two copies of `child-run.ts` (§8.5.1); every
  command form, through each copy, over the hostile repository with a
  poisoned parent environment. The fixture's config hooks (one per hook
  event, one more in the included file): a stock commit springs them
  exactly on a git that runs them (2.54+); on 2.55+ the forced config
  without its event switches still springs them and with them springs none;
  on 2.54 fs-sync's commit springs only a commit's config hooks (§8.6's
  residual, pinned) and every other form none. The CI guests' git
  (Ubuntu's, older than 2.54) runs no config hooks, so there the control is
  what holds; the runs under 2.54, 2.55 and 2.56 were made by hand with each
  git first on `PATH` (2026-10-17: the unit file's hook cases, this file and
  `tests/stack/git-hardening.test.ts` green on all three, and the unit hook
  case red on 2.55 and 2.56 with the switches taken out).
- `launcher/test/unit/git-runner.test.ts` (§8.5.1): the launcher's
  `defaultGitRunner` through `runChild`, with a stand-in `git`: exit code,
  output and input; the deadline kills the call's whole group (a background
  process dies too) and fails the call; a process outside the group holding
  the output fails the call after the close grace. The git session (§8.5.3),
  its runner bare (no privilege): answers byte-identical to the per-call
  runner's over a real repository (non-UTF-8 output over a pipe's size,
  stdin, an environment, exit 1 and 128, a missing cwd), argv and the
  environment passed exactly, twenty concurrent calls kept apart; a deadline
  kills only its call's group; an exit kills what the call left in its
  group; a straggler outside the group, the runner killed, an unreadable
  frame each fail the calls in flight and end the session (later calls run
  per call); a runner never ready, or one framing an answer before it is,
  runs nothing (its calls run per call); `close()`; writes, no sandbox and
  Seatbelt run per call; an idle unclosed session does not hold the process;
  Yama `ptrace_scope` 0, absent or unreadable runs every call per call; the
  session's flags replace `--proc /proc` by an empty read-only tmpfs after
  the root bind.
- `launcher/test/kernel/git-sandbox.test.ts` (`sandbox` kind, self-SKIPs): a
  program git runs inside the sandbox cannot write outside the bound
  directory or into the repository, reaches no network, holds no
  capability; the production runner still rebuilds a sanitized pack
  (`index-pack` writes through its bind); and 256 production-runner calls
  whose 1-8 ms deadlines land in bubblewrap's start-up all settle and leave
  no sandbox child behind (§8.5.1). The git session in the real sandbox
  (§8.5.3): every call in one pid and net namespace (not the host's, read
  from the host's `/proc`), with no capability, nothing written and an empty
  `/proc`, where the per-call runner makes one per call; a call finds no
  `/proc/<pid>/fd`, `environ`, `mem` or `status` of a sibling call, the
  runner, the host's test process or itself, and cannot write `/proc`
  (while the same probe opens them in the per-call sandbox), and real git
  (`rev-parse`, `log`, `rev-list`, `ls-files`, `cat-file`, `for-each-ref`,
  `config`) works there; answers byte-identical to the per-call sandboxed runner's (128 +
  SIGTERM in both); a deadline kills only its call, and a straggler or the
  runner killed ends the sandbox, fails the calls in flight and leaves no
  process behind. `launcher/test/kernel/git-object-twins.test.ts`: the
  step's twins, sanitized packs and locked ids through a session equal the
  per-call runner's, and a runner killed under the step refuses it.
- `tests/sandbox/prepared-copies-sandbox.test.ts` (kernel
  tier, self-SKIPs): a program started inside an R3 build's sandbox (its own
  command line, `prepGitCommand`) writes only in the build's work
  directory, not into another copy in the same cache, the cache itself or
  the repository; the production preparer, sandboxed, builds and seals a
  copy without the locked id.

The oracle tests turn the sandbox off (`MANDU_GIT_SANDBOX=0`): a marker
inside it could not write, and it is the hardening that is under test.

## 9. macOS: the Seatbelt profile refuses (2026-09-29)

macOS has no guard (no seccomp user notification), so the same list is
enforced by the whole-agent Seatbelt profile (confidentiality.md §7.3,
`launcher/src/seatbelt-profile.ts` component 3), in the same modes (every mode
but `off`; `MANDU_WRITE_PROTECT=0` opts out) and with the same
policy.yaml `write_protect:` additions and opt-outs (read from the arbiter as
on Linux). The differences:

- **Every entry is refused, `ask` included.** A Seatbelt rule is decided in
  the kernel with no one to ask, so there is no Inbox hold: a change to a
  shell startup file, a launchd agent, an ssh or git setting or a repo hook
  fails with EPERM. The launch says so (`… are REFUSED on macOS: the Seatbelt
  profile cannot hold a change for your OK in the Inbox`).
- **`~/Library/LaunchAgents` joins the files that run later**
  (`laterRunFiles(env, "darwin")`), under the existing label "a desktop
  autostart entry" (the labels are the arbiter's, pinned by the parity
  test): a plist there runs at the next login or `launchctl load`.
- **xcrun's per-user cache joins them too (2026-09-30)**:
  `$(getconf DARWIN_USER_TEMP_DIR)xcrun_db`, the file that names the binary
  Apple's `/usr/bin/git` (and every other xcrun shim in `/usr/bin`) runs.
  The user owns it, so the agent could point the user's next `git` at a
  program of its own; Mandu's own git calls ignore it (`xcrun_nocache=1`,
  write-protection.md §8.5.2). Refused like every other entry here; measured on
  macOS 26.5: git still works with the cache write-denied, and a rename
  over it is refused.
- **The rule.** `deny file-write*` on the entry as a `subpath` (it covers a
  file and everything under a directory: write, create, truncate, rename,
  delete, link, mode), in the given spelling and the canonical one, plus
  `deny file-write-unlink` (a literal) on every folder above it, so the
  protected tree cannot be renamed out from under the rule. A symlinked
  entry protects its target too, as the guard judges the file a write
  resolves to.
- **The arbiter socket's own entries are literal.** They name the socket and
  the links on its way (`current`, and on macOS `/tmp` → `/private/tmp`
  itself): following `/tmp` would seal all of `/private/tmp`. Literal on the
  link keeps the link from being replaced; the socket file itself is
  write-denied (a connect to it still works: Seatbelt judges a connect as
  `network-outbound`, not as a write).
- **An entry that would seal the workspace, Mandu's runtime or session
  directory is left out**, with one WARNING (a policy.yaml `deny: ["~"]`
  would otherwise stop the session).
- **Beyond the list, Mandu's runtime registries (2026-09-30).** The runtime
  directory itself stays writable (the session's dir is in it), but the
  entries in it that Mandu processes outside the profile write through or
  delete from (`instances/`, `current`, the promotion's `.current.tmp-*`,
  the legacy `arbiter.sock`, `dashboards/`, `mandu dashboard`'s
  `dashboard.log` and `dashboard-*` port files, `vm-guests/`, `logs/`, `release-check/`,
  `test/`; `launcher/src/runtime-registry.ts`), in the launch's runtime
  directory and the account's default one, are write-denied by a component
  of their own, in every mode but `off` and whatever `MANDU_WRITE_PROTECT`
  says (confidentiality.md §7.3; runtime-instances.md §2, "planted paths").
  Unlike the list's, an entry that holds the workspace or the session's
  directory refuses the launch. The Linux list carries the same entries
  (2026-10-07, §2 "Mandu's runtime registries").
- The `write_protect:` extended-attribute and chmod residuals of §4 do not
  apply (`file-write*` covers `file-write-xattr` and `file-write-mode`); the
  host-service residual is narrowed by the profile's host-service rules
  (confidentiality.md §7.3) and remains for Mach/XPC launches.
