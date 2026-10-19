# scripts/apparmor — Mandu's own bubblewrap for Ubuntu's userns restriction

## Why

Ubuntu 23.10+ ships `kernel.apparmor_restrict_unprivileged_userns = 1`
(`/usr/lib/sysctl.d/10-apparmor.conf`). With it, an unprivileged process may
create a user namespace only when the binary it execs carries an AppArmor
profile that grants `userns`. Ubuntu 25.04+ also ships its own profile for
`/usr/bin/bwrap` (`bwrap-userns-restrict`) that grants it, but bars every
program inside a bwrap sandbox from starting another one, so the secret mount
layer would stop Codex's shell and Mandu's command box.

Without `mandu setup` Mandu still confines secrets on both: the whole-agent
guard serves the placeholder copies by descriptor. The mount layer is the
optional second layer (`docs/design/confidentiality/rootless-confinement-ubuntu-2404.md`
§11-§12).

## What

- `mandu-bwrap`: the profile `mandu setup` installs as
  `/etc/apparmor.d/mandu-bwrap`, for a copy of the system bwrap at the
  root-owned `/usr/lib/mandu/bin/bwrap`. Two Mandu-named profiles:
  `mandu_bwrap` (the copy: userns, capabilities, mounts) and `mandu_child`
  (everything it runs: no capabilities and no user namespace, except bwrap
  itself, which runs as `mandu_bwrap` again). So a sandbox can start inside
  Mandu's, `unshare -Ur` inside it is refused, and running the copy by hand
  gives nobody a namespace with capabilities. It attaches to Mandu's path
  only and shares no profile name with anything Ubuntu ships.
- `mandu-dev-unshare`: a DEVELOPER-ONLY grant for `scripts/kernel-tests.sh`
  (it runs the kernel tests under `unshare --user`). Host-wide by nature:
  keep it off anything that is not a development box.
- `install.sh`: the same install from a git checkout; `--dev-unshare` adds
  the developer grant.

```sh
mandu setup                                  # the end-user path: explains, asks, runs sudo itself
sudo scripts/apparmor/install.sh             # the same install from a git checkout
sudo scripts/apparmor/install.sh --dev-unshare
```

`mandu setup` (`launcher/src/setup.ts`, `launcher/src/bwrap-grant.ts`) ships
`mandu-bwrap` inside the npm package, prints it with `--print`, removes it
with `--uninstall`, and never touches a file it did not create (the
`# Mandu:` first line is the ownership marker, so keep it).

## The grants before 2026-09-27, and why they are gone

Mandu used to install `profile bwrap /usr/bin/bwrap flags=(unconfined) {
userns, }` and the same for `/usr/bin/unshare`. Both let every program on the
host create a user namespace with capabilities (the trampoline the restriction
exists to prevent), and the `bwrap` one shares its profile NAME with Ubuntu's:
whichever file loads last wins, so on a 24.04 host upgraded to 26.04 it
silently switched Ubuntu's restriction off for every program. `mandu setup`
now removes a Mandu-marked `/etc/apparmor.d/bwrap` or `unshare`: it deletes
the file and reloads Ubuntu's file that defines the same name, instead of
unloading by name (which would unload Ubuntu's profile too). `mandu doctor`
flags a leftover.

## The sysctl alternative, and why it is not the default

`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` (persisted
under `/etc/sysctl.d/`) lifts the restriction for every binary on the host.
It works, but it widens host-global state, which the non-root principle
(`docs/design/architecture/privilege-model.md` §0) treats as a last resort. Mandu's own
bubblewrap gives the one program Mandu runs the capability it needs, and
nothing else. Either way this is a one-time host admin step; Mandu itself
never needs root at runtime.
