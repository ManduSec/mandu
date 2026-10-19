import { test } from "node:test";
import assert from "node:assert/strict";
import {
  gatherWslFacts,
  hostIsWsl,
  interopState,
  isWindowsDrive,
  kernelVersion,
  parseMountinfo,
  windowsDriveMount,
  windowsProfiles,
  windowsProfileSecretRoots,
  WINDOWS_PROFILE_SECRET_PATHS,
  wslLaunchNotes,
  wslTwinWrapFlags,
  wslVersion,
  type WslFacts,
} from "../../src/wsl.js";

// The SAME strings as mandu_arbiter::wsl's `the_kernel_release_names_the_generation`
// (Rust): the launcher and the boxes must agree on what WSL is.
test("wslVersion: parity with mandu_arbiter::wsl on the kernel release strings", () => {
  assert.equal(wslVersion("5.15.167.4-microsoft-standard-WSL2"), 2);
  assert.equal(wslVersion("6.6.36.6-microsoft-standard-WSL2+"), 2);
  assert.equal(wslVersion("4.19.104-microsoft-standard"), 2);
  assert.equal(wslVersion("4.4.0-19041-Microsoft"), 1);
  assert.equal(wslVersion("6.8.0-139-generic"), null);
  assert.equal(wslVersion(""), null);
  assert.equal(wslVersion(null), null);
});

test("hostIsWsl: any one signal (kernel release, $WSL_INTEROP, the binfmt entry)", () => {
  const none = { readFile: () => "6.8.0-139-generic", fileExists: () => false, env: {} };
  assert.equal(hostIsWsl(none), false);
  assert.equal(hostIsWsl({ ...none, readFile: () => "5.15.1-microsoft-standard-WSL2" }), true);
  assert.equal(hostIsWsl({ ...none, env: { WSL_INTEROP: "/run/WSL/8_interop" } }), true);
  assert.equal(hostIsWsl({ ...none, env: { WSL_INTEROP: "" } }), false);
  assert.equal(hostIsWsl({ ...none, fileExists: (p) => p === "/proc/sys/fs/binfmt_misc/WSLInterop" }), true);
});

test("kernelVersion and interopState", () => {
  assert.deepEqual(kernelVersion("5.10.102.1-microsoft-standard-WSL2"), [5, 10]);
  assert.deepEqual(kernelVersion("6.6.36.6-microsoft-standard-WSL2"), [6, 6]);
  assert.equal(kernelVersion("garbage"), null);
  assert.equal(interopState(null), "absent");
  assert.equal(interopState("enabled\ninterpreter /init\nflags: PF\n"), "enabled");
  assert.equal(interopState("disabled\ninterpreter /init\n"), "disabled");
});

// A WSL2 mountinfo: / on ext4, /mnt/c drvfs over 9p, /mnt/d on virtiofs, a
// drive mount point with an escaped space, and /mnt/wsl (tmpfs, not a drive).
const MOUNTINFO = [
  "61 1 8:32 / / rw,relatime - ext4 /dev/sdc rw,discard,errors=remount-ro",
  "80 61 0:59 / /mnt/c rw,noatime - 9p C:\\134 rw,dirsync,aname=drvfs;path=C:\;uid=1000;gid=1000,trans=fd,rfd=5,wfd=5",
  "81 61 0:60 / /mnt/d rw,noatime - virtiofs D:\\134 rw",
  "82 61 0:61 / /mnt/my\\040drive rw,noatime - drvfs E:\\134 rw",
  "83 61 0:62 / /mnt/wsl rw,relatime - tmpfs none rw",
  "garbage line",
].join("\n");

test("parseMountinfo: fields after the separator, octal escapes undone, garbage skipped", () => {
  const m = parseMountinfo(MOUNTINFO);
  assert.equal(m.length, 5);
  assert.deepEqual(m[1], { mountPoint: "/mnt/c", fstype: "9p", source: "C:\\", superOptions: "rw,dirsync,aname=drvfs;path=C:\;uid=1000;gid=1000,trans=fd,rfd=5,wfd=5" });
  assert.equal(m[3]!.mountPoint, "/mnt/my drive");
});

test("windowsDriveMount: a project under /mnt/c (and d, e) is on a Windows drive; ~ and /mnt/wsl are not", () => {
  const m = parseMountinfo(MOUNTINFO);
  assert.equal(windowsDriveMount("/mnt/c/Users/me/proj", m)?.mountPoint, "/mnt/c");
  assert.equal(windowsDriveMount("/mnt/c", m)?.mountPoint, "/mnt/c");
  assert.equal(windowsDriveMount("/mnt/d/src", m)?.mountPoint, "/mnt/d");
  assert.equal(windowsDriveMount("/mnt/my drive/x", m)?.mountPoint, "/mnt/my drive");
  assert.equal(windowsDriveMount("/home/me/proj", m), null);
  assert.equal(windowsDriveMount("/mnt/wsl/x", m), null);
  assert.equal(windowsDriveMount("/mnt/cx/proj", m), null, "component-exact");
  // A plain 9p mount that is not drvfs (a VM share) is not a Windows drive.
  assert.equal(isWindowsDrive({ mountPoint: "/srv", fstype: "9p", source: "share", superOptions: "trans=virtio" }), false);
});

function facts(over: Partial<WslFacts> = {}): WslFacts {
  return {
    version: 2, kernel: "6.6.36.6-microsoft-standard-WSL2", landlock: true, landlockNet: false,
    interop: "enabled", systemd: true, workspaceDrive: null, ...over,
  };
}

test("gatherWslFacts: null off WSL; the gates, interop, systemd and drive from the host reads", () => {
  const files: Record<string, string> = {
    "/proc/sys/kernel/osrelease": "5.10.102.1-microsoft-standard-WSL2\n",
    "/proc/sys/fs/binfmt_misc/WSLInterop": "enabled\ninterpreter /init\n",
    "/proc/self/mountinfo": MOUNTINFO,
  };
  const deps = { readFile: (p: string) => files[p] ?? null, fileExists: () => false, cwd: "/mnt/c/Users/me/proj" };
  assert.deepEqual(gatherWslFacts(deps), {
    version: 2, kernel: "5.10.102.1-microsoft-standard-WSL2", landlock: false, landlockNet: false,
    interop: "enabled", systemd: false, workspaceDrive: { path: "/mnt/c/Users/me/proj", mountPoint: "/mnt/c" },
  });
  assert.equal(gatherWslFacts({ ...deps, readFile: (p) => (p === "/proc/sys/kernel/osrelease" ? "6.8.0-139-generic" : null) }), null);
  const six = gatherWslFacts({ ...deps, readFile: (p) => (p === "/proc/sys/kernel/osrelease" ? "6.6.1-microsoft-standard-WSL2" : null), fileExists: (p) => p === "/run/systemd/system", cwd: "/home/me" })!;
  assert.equal(six.landlock, true);
  assert.equal(six.landlockNet, false);
  assert.equal(six.interop, "absent");
  assert.equal(six.systemd, true);
  assert.equal(six.workspaceDrive, null);
});

test("wslTwinWrapFlags: interop dir + /init hidden and WSL_INTEROP dropped on WSL only; missing paths skipped", () => {
  assert.deepEqual(wslTwinWrapFlags(false, () => true), []);
  assert.deepEqual(wslTwinWrapFlags(true, () => true), [
    "--tmpfs", "/run/WSL", "--ro-bind", "/dev/null", "/init", "--unsetenv", "WSL_INTEROP",
  ]);
  assert.deepEqual(wslTwinWrapFlags(true, () => false), ["--unsetenv", "WSL_INTEROP"]);
  assert.ok(!wslTwinWrapFlags(true, () => true).includes("/mnt/wslg"), "the live agent keeps WSLg");
});

test("wslLaunchNotes: interop with and without the guard, old kernel, Windows drive, WSL1", () => {
  assert.deepEqual(wslLaunchNotes(null, { guard: true }), []);
  const guarded = wslLaunchNotes(facts(), { guard: true });
  assert.equal(guarded.length, 1);
  assert.match(guarded[0]!, /^mandu: WSL2 .*connect guard refuses the interop socket and AF_VSOCK/);
  const open = wslLaunchNotes(facts(), { guard: false });
  assert.match(open[0]!, /^WARNING: mandu: WSL2 .*runs outside Mandu.*\[interop\] enabled=false/);
  assert.deepEqual(wslLaunchNotes(facts({ interop: "disabled" }), { guard: false }), []);
  assert.match(wslLaunchNotes(facts({ interop: "absent", landlock: false }), { guard: true })[0]!, /predates Landlock.*wsl --update/);
  const drive = wslLaunchNotes(facts({ interop: "disabled", workspaceDrive: { path: "/mnt/c/p", mountPoint: "/mnt/c" } }), { guard: true });
  assert.match(drive[0]!, /^WARNING: .*\/mnt\/c\/p is on a Windows drive \(\/mnt\/c\).*Linux file system/);
  const one = wslLaunchNotes(facts({ version: 1 }), { guard: true });
  assert.equal(one.length, 1);
  assert.match(one[0]!, /WSL1.*wsl --set-version <distro> 2/);
});

test("windowsProfiles: each drive's Users/<name> from the mount table; shared, template, junction and dot entries skipped", () => {
  const listings: Record<string, Array<{ name: string; dir: boolean }>> = {
    "/mnt/c/Users": [
      { name: "alice", dir: true }, { name: "Public", dir: true }, { name: "Default", dir: true },
      { name: "Default User", dir: false }, { name: "All Users", dir: false }, { name: "desktop.ini", dir: false },
      { name: "DEFAULT", dir: true }, { name: ".hidden", dir: true }, { name: "Bob Smith", dir: true },
    ],
    "/mnt/d/Users": [{ name: "carol", dir: true }],
    // /mnt/wsl is tmpfs, not a drive: never listed even if it had a Users dir.
    "/mnt/wsl/Users": [{ name: "mallory", dir: true }],
  };
  const asked: string[] = [];
  const got = windowsProfiles(parseMountinfo(MOUNTINFO), (p) => { asked.push(p); return listings[p] ?? null; });
  assert.deepEqual(got, ["/mnt/c/Users/Bob Smith", "/mnt/c/Users/alice", "/mnt/d/Users/carol"]);
  assert.ok(!asked.includes("/mnt/wsl/Users"), "only Windows drives are listed");
  assert.ok(asked.includes("/mnt/my drive/Users"), "an automount root with a space is still a drive");
  // A custom automount root ([automount] root = /win/) is read from the table.
  const custom = parseMountinfo("90 61 0:70 / /win/c rw - 9p C:\\134 rw,aname=drvfs;path=C:\\");
  assert.deepEqual(windowsProfiles(custom, (p) => (p === "/win/c/Users" ? [{ name: "dev", dir: true }] : null)), ["/win/c/Users/dev"]);
  // Off WSL (no drive in the table) nothing is probed at all.
  assert.deepEqual(windowsProfiles(parseMountinfo("61 1 8:32 / / rw - ext4 /dev/sda rw"), () => { throw new Error("probed"); }), []);
});

test("windowsProfileSecretRoots: the catalog's stores plus the Windows spellings, under the profile", () => {
  const roots = windowsProfileSecretRoots("/mnt/c/Users/alice/");
  assert.equal(roots.length, WINDOWS_PROFILE_SECRET_PATHS.length);
  for (const want of [".aws", ".ssh", ".kube", ".docker/config.json", ".azure", ".git-credentials", ".npmrc", ".netrc", "_netrc", "AppData/Roaming/gcloud"]) {
    assert.ok(roots.includes(`/mnt/c/Users/alice/${want}`), want);
  }
  assert.ok(roots.every((r) => r.startsWith("/mnt/c/Users/alice/") && !r.includes("//")));
  assert.equal(new Set(WINDOWS_PROFILE_SECRET_PATHS).size, WINDOWS_PROFILE_SECRET_PATHS.length, "no duplicates");
});
