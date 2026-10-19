//! git_lock — the guard's backstop for locked git objects
//! (confidentiality-plan-14-policy-suggestions.md §11.1 R4, 2026-09-30).
//!
//! A lock (a `blobs:` id, or a labelled path's committed versions) is
//! enforced by the object twins only in the repositories the launch prepared
//! (confidentiality.md §7.2a). Any other repository that holds the same blob
//! (another checkout, a clone, a fork) kept it readable. The launcher now
//! hands the guard the LOCKED SET, the ids of every locked object it knows
//! (`gitLocks.ids` in the guard policy file), and the guard checks the files
//! that could hold one:
//!
//!   - a pack or a companion (`pack-<id>.pack`, `.idx`, `.rev`, `.bitmap`,
//!     `.mtimes`, anywhere; any such extension under `objects/pack/`): the
//!     set is looked up in the pack's `.idx` (the fanout table and a binary
//!     search per locked id, as launcher git-object-twins.ts `idxLookup`
//!     does), which the guard opens itself, in its own view, next to the file
//!     the tracee opened and pinned to it by identity;
//!   - a multi-pack index (`multi-pack-index`, its bitmap and reverse index,
//!     an incremental layer): every `.idx` of its pack directory;
//!   - a loose object: its name is its id (a leaf of 38 or 62 hex digits; the
//!     two-digit directory is not required, so renaming it away changes
//!     nothing);
//!   - git's temporary files of object content (`tmp_pack_*`, a pack being
//!     written; `tmp_obj_*`, a loose object being written; 2026-10-17):
//!     they have no index yet, so nothing tells what they hold. One a
//!     process of the session created (an exclusive create the guard
//!     performed, remembered by path and identity, `created`) holds what
//!     that process wrote; any other one (a `git gc` or `git fetch` the
//!     person runs outside the session, mid-write, holding every object of
//!     the repository) is UNKNOWN.
//!
//! A file whose verdict is LOCKED is refused; so is one whose verdict cannot
//! be reached (UNKNOWN: an index that does not parse, a pack with no index, a
//! file that moved while it was checked, a temporary file of object content
//! the session did not create): fail closed. A pack holding a locked
//! object for which the launch prepared a sanitized copy never gets here: it
//! is a registered `object` entry and served its twin before this check.
//!
//! The rest of the rules keep a locked object from leaving its checked name:
//! a rename or hard link whose source is such a file is refused, and the
//! index, the anchor of every verdict, cannot be removed, replaced or
//! truncated while it anchors a pack (`refuses`; an index whose pack is gone
//! may be removed, `removal_access`, 2026-10-16). Only a refusal of a read
//! is reported to the person (`reported`). Everything else
//! about an object store (git's temporary index files, new packs, `.keep`)
//! runs untouched.
//!
//! PURE except `GitLockGuard`'s filesystem reads (openat / fstatat / pread /
//! readdir, no privilege, no seccomp): the whole module is compiled and
//! unit-tested in the default build; the notification handlers that call it
//! are `guard_kernel`. `Mandu-new`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::sync::Mutex;

/// The version-2 pack index magic (`\377tOc`).
pub const IDX_MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];

/// A repository's object format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    Sha1,
    Sha256,
}

impl Format {
    /// The raw hash length.
    // A digest's length is never zero, so an `is_empty` would be dead code.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(self) -> usize {
        match self {
            Format::Sha1 => 20,
            Format::Sha256 => 32,
        }
    }
    fn of_len(n: usize) -> Option<Format> {
        match n {
            20 => Some(Format::Sha1),
            32 => Some(Format::Sha256),
            _ => None,
        }
    }
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Lowercase hex to bytes; `None` for an odd length or any other character.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if b.len() % 2 != 0 {
        return None;
    }
    b.chunks(2).map(|p| Some(hex_val(p[0])? << 4 | hex_val(p[1])?)).collect()
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| hex_val(c).is_some())
}

/// A locked id as the policy file writes it: `sha1:<40 hex>` or
/// `sha256:<64 hex>`, lowercase (the arbiter's `BLOB_ID_RE`). Pure.
pub fn parse_id(id: &str) -> Option<(Format, Vec<u8>)> {
    let (fmt, hex) = if let Some(h) = id.strip_prefix("sha1:") {
        (Format::Sha1, h)
    } else if let Some(h) = id.strip_prefix("sha256:") {
        (Format::Sha256, h)
    } else {
        return None;
    };
    let raw = hex_decode(hex)?;
    (raw.len() == fmt.len()).then_some((fmt, raw))
}

/// The empty blob in both formats: it holds no byte to protect, and a
/// protected file that was once empty would otherwise lock every repository
/// holding an empty file (launcher git-lock-backstop.ts drops it too).
pub const EMPTY_BLOB_IDS: [&str; 2] = [
    "sha1:e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
    "sha256:473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813",
];

/// The locked set: each format's raw ids, sorted, and the loose-object leaf
/// of each (the id without its first two hex digits).
#[derive(Debug, Default, Clone)]
pub struct LockedSet {
    sha1: Vec<Vec<u8>>,
    sha256: Vec<Vec<u8>>,
    loose: HashSet<String>,
}

impl LockedSet {
    /// The set of the ids given, and the ones that are not ids (the caller
    /// says so; a launcher writes only valid ones). The empty blob is never
    /// locked (`EMPTY_BLOB_IDS`). Pure.
    pub fn from_ids<'a>(ids: impl IntoIterator<Item = &'a str>) -> (LockedSet, Vec<String>) {
        let mut set = LockedSet::default();
        let mut bad = Vec::new();
        for id in ids {
            if EMPTY_BLOB_IDS.contains(&id) {
                continue;
            }
            match parse_id(id) {
                Some((fmt, raw)) => {
                    let hex = &id[id.find(':').unwrap() + 1..];
                    set.loose.insert(hex[2..].to_string());
                    match fmt {
                        Format::Sha1 => set.sha1.push(raw),
                        Format::Sha256 => set.sha256.push(raw),
                    }
                }
                None => bad.push(id.to_string()),
            }
        }
        for v in [&mut set.sha1, &mut set.sha256] {
            v.sort();
            v.dedup();
        }
        (set, bad)
    }

    pub fn is_empty(&self) -> bool {
        self.sha1.is_empty() && self.sha256.is_empty()
    }

    pub fn len(&self) -> usize {
        self.sha1.len() + self.sha256.len()
    }

    /// The raw ids of one format, sorted.
    pub fn names(&self, fmt: Format) -> &[Vec<u8>] {
        match fmt {
            Format::Sha1 => &self.sha1,
            Format::Sha256 => &self.sha256,
        }
    }

    /// Is a loose object with this leaf name locked? Pure.
    pub fn loose_locked(&self, leaf: &str) -> bool {
        self.loose.contains(leaf)
    }
}

// ── the prefilter: which paths name an object-store file ─────────────────────

/// A pack's companion files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackExt {
    Pack,
    Idx,
    Rev,
    Bitmap,
    Mtimes,
}

impl PackExt {
    fn parse(s: &str) -> Option<PackExt> {
        Some(match s {
            "pack" => PackExt::Pack,
            "idx" => PackExt::Idx,
            "rev" => PackExt::Rev,
            "bitmap" => PackExt::Bitmap,
            "mtimes" => PackExt::Mtimes,
            _ => return None,
        })
    }
}

/// An object-store file, as its path names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreFile {
    /// A pack or a companion: `dir` holds it, `base` is its name without
    /// the extension (the `.idx` is `dir/base.idx`).
    Pack { dir: String, base: String, ext: PackExt },
    /// A multi-pack index, its bitmap or reverse index, or an incremental
    /// layer: `pack_dir` is the directory whose `.idx` files it covers.
    Midx { pack_dir: String },
    /// A loose object: `leaf` is its id without the first two hex digits.
    Loose { leaf: String },
    /// One of git's temporary files that holds object CONTENT while it is
    /// written (`tmp_pack_*`, `tmp_obj_*`: the names git's `odb_mkstemp` and
    /// `create_tmpfile` make, `O_CREAT|O_EXCL`, before linking or renaming
    /// the file to its final name). Its temporary index files (`tmp_idx_*`,
    /// `tmp_rev_*`, …) hold ids, never content, and are not this.
    Temp,
}

/// The leaf prefixes of git's temporary files that hold object content.
pub const TEMP_PREFIXES: [&str; 2] = ["tmp_pack_", "tmp_obj_"];

/// ` (deleted)`: what the kernel appends to the path of a descriptor whose
/// name is gone. A file unlinked after it was pinned is still classified by
/// the name it had (its anchor check then fails: UNKNOWN, refused).
const DELETED: &str = " (deleted)";

fn split(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

fn last(path: &str) -> &str {
    split(path).1
}

/// Is `base` a pack's own name (`pack-<40 or 64 hex>`)?
fn is_pack_base(base: &str) -> bool {
    base.strip_prefix("pack-").is_some_and(|h| (h.len() == 40 || h.len() == 64) && is_lower_hex(h))
}

/// The prefilter: the object-store file an absolute path names, or `None`
/// for every other path (continued at once). Lexical only. Pure.
pub fn classify(path: &str) -> Option<StoreFile> {
    let path = path.strip_suffix(DELETED).unwrap_or(path);
    let (dir, leaf) = split(path);
    if leaf.is_empty() {
        return None;
    }
    // A loose object: its leaf is the rest of its id.
    if (leaf.len() == 38 || leaf.len() == 62) && is_lower_hex(leaf) {
        return Some(StoreFile::Loose { leaf: leaf.to_string() });
    }
    // Git's object content being written (anywhere: a renamed directory
    // changes nothing, as for a loose object).
    if TEMP_PREFIXES.iter().any(|p| leaf.len() > p.len() && leaf.starts_with(p)) {
        return Some(StoreFile::Temp);
    }
    if let Some(dot) = leaf.rfind('.') {
        let (base, ext) = (&leaf[..dot], &leaf[dot + 1..]);
        // Multi-pack index companions and incremental layers.
        if let Some(h) = base.strip_prefix("multi-pack-index-") {
            if is_lower_hex(h) {
                if matches!(ext, "bitmap" | "rev") && last(dir) != "multi-pack-index.d" {
                    return Some(StoreFile::Midx { pack_dir: dir.to_string() });
                }
                if matches!(ext, "midx" | "bitmap" | "rev") && last(dir) == "multi-pack-index.d" {
                    return Some(StoreFile::Midx { pack_dir: split(dir).0.to_string() });
                }
            }
        }
        if let Some(e) = PackExt::parse(ext) {
            let in_pack_dir = last(dir) == "pack" && last(split(dir).0) == "objects";
            if !base.is_empty() && (is_pack_base(base) || in_pack_dir) {
                return Some(StoreFile::Pack { dir: dir.to_string(), base: base.to_string(), ext: e });
            }
        }
    }
    if leaf == "multi-pack-index" {
        return Some(StoreFile::Midx { pack_dir: dir.to_string() });
    }
    None
}

/// The repository a store file belongs to, for the person: the work tree
/// above `<…>/.git/objects`, the git directory of a bare one, or the file's
/// own directory when no `objects` component is left (a moved pack). Pure.
pub fn repo_of(path: &str) -> String {
    let path = path.strip_suffix(DELETED).unwrap_or(path);
    if let Some(i) = path.rfind("/objects/") {
        let git_dir = &path[..i];
        return git_dir.strip_suffix("/.git").filter(|r| !r.is_empty()).unwrap_or(if git_dir.is_empty() { "/" } else { git_dir }).to_string();
    }
    let d = split(path).0;
    if d.is_empty() { "/".into() } else { d.to_string() }
}

// ── the pack index ───────────────────────────────────────────────────────────

/// Why an index gave no answer. Every one is a refusal (fail closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdxError {
    TooSmall,
    /// Magic present but a version other than 2.
    BadVersion(u32),
    /// A fanout table that decreases.
    BadFanout,
    /// The size fits neither a SHA-1 nor a SHA-256 index of this count.
    BadSize,
    /// A read came back short.
    Truncated,
    Io(i32),
}

impl std::fmt::Display for IdxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdxError::TooSmall => write!(f, "the pack index is too small"),
            IdxError::BadVersion(v) => write!(f, "the pack index is version {v}"),
            IdxError::BadFanout => write!(f, "the pack index's fanout table is not monotonic"),
            IdxError::BadSize => write!(f, "the pack index's size does not match its object count"),
            IdxError::Truncated => write!(f, "the pack index is truncated"),
            IdxError::Io(e) => write!(f, "the pack index could not be read (errno {e})"),
        }
    }
}

/// Where a pack index keeps its names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdxLayout {
    pub version: u32,
    pub format: Format,
    pub count: u32,
    pub fanout: Vec<u32>,
    /// Offset of the first name.
    pub first: u64,
    /// Bytes from one name to the next.
    pub stride: u64,
}

/// The layout of a pack index from its first 1032 bytes (fewer for a tiny
/// file) and its size. Version 2 (`\377tOc`, version 2, fanout, names, CRCs,
/// offsets, large offsets, two trailing hashes): its hash length is the one
/// its size admits (a SHA-1 and a SHA-256 index of the same count never have
/// the same size); version 1 (no magic: fanout, then 24-byte entries of a
/// 4-byte offset and a SHA-1 name, two trailing hashes) is SHA-1 only. Pure.
pub fn idx_layout(head: &[u8], size: u64) -> Result<IdxLayout, IdxError> {
    let fan_at = |at: usize| -> Result<Vec<u32>, IdxError> {
        if head.len() < at + 1024 {
            return Err(IdxError::TooSmall);
        }
        let f: Vec<u32> = (0..256).map(|i| u32::from_be_bytes(head[at + i * 4..at + i * 4 + 4].try_into().unwrap())).collect();
        if f.windows(2).any(|w| w[1] < w[0]) {
            return Err(IdxError::BadFanout);
        }
        Ok(f)
    };
    if head.len() >= 8 && head[..4] == IDX_MAGIC {
        let version = u32::from_be_bytes(head[4..8].try_into().unwrap());
        if version != 2 {
            return Err(IdxError::BadVersion(version));
        }
        let fanout = fan_at(8)?;
        let n = fanout[255] as u64;
        let fits = |h: u64| -> bool {
            let base = 8 + 1024 + n * (h + 8) + 2 * h;
            size >= base && (size - base) % 8 == 0 && (size - base) / 8 <= n
        };
        let format = match (fits(20), fits(32)) {
            (true, false) => Format::Sha1,
            (false, true) => Format::Sha256,
            _ => return Err(IdxError::BadSize),
        };
        return Ok(IdxLayout { version, format, count: fanout[255], fanout, first: 8 + 1024, stride: format.len() as u64 });
    }
    let fanout = fan_at(0)?;
    let n = fanout[255] as u64;
    if size != 1024 + 24 * n + 40 {
        return Err(IdxError::BadSize);
    }
    Ok(IdxLayout { version: 1, format: Format::Sha1, count: fanout[255], fanout, first: 1024 + 4, stride: 24 })
}

/// Does the index list any of `names` (raw ids of its format)? The fanout
/// narrows each to its bucket and a binary search reads only the names it
/// visits (`read(offset, len)`: short at the end of the file). Pure given
/// `read`.
pub fn idx_holds_any(layout: &IdxLayout, names: &[Vec<u8>], read: &dyn Fn(u64, usize) -> Result<Vec<u8>, IdxError>) -> Result<bool, IdxError> {
    let h = layout.format.len();
    let fan = |b: i32| -> u32 { if b < 0 { 0 } else { layout.fanout[b as usize] } };
    for want in names {
        if want.len() != h {
            continue;
        }
        let (mut lo, mut hi) = (fan(want[0] as i32 - 1), fan(want[0] as i32));
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let got = read(layout.first + mid as u64 * layout.stride, h)?;
            if got.len() < h {
                return Err(IdxError::Truncated);
            }
            match got.as_slice().cmp(want.as_slice()) {
                std::cmp::Ordering::Equal => return Ok(true),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
    }
    Ok(false)
}

// ── verdicts and the rules ───────────────────────────────────────────────────

/// What a store file holds, as far as the guard can tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No locked id.
    Clean,
    /// A locked id (a pack or companion whose index lists one; a multi-pack
    /// index over such a pack; a locked loose object).
    Locked,
    /// No answer (why): refused like `Locked`.
    Unknown(String),
}

/// What a tracee is doing to a store file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Any open that reaches the file (a read, a write, both).
    Open,
    /// A rename's source: the file leaves its checked name.
    RenameSrc,
    /// A hard link's source: the file gets a name no one checks.
    LinkSource,
    /// An unlink.
    Remove,
    /// An unlink of a pack's INDEX whose pack is gone from the directory the
    /// unlink acts on (`removal_access`): the index anchors nothing.
    RemoveOrphanIndex,
    /// An existing file a rename replaces.
    ReplaceDest,
    /// A `truncate` by path.
    Truncate,
}

/// Is `access` to `file` refused, given its verdict? A clean file never is.
/// Otherwise an open, a rename and a hard link always are; removing,
/// replacing or truncating only the INDEX is (it anchors the verdict of its
/// pack: with it gone or rewritten, the pack's bytes would be judged by a
/// file the tracee chose; a pack itself, a companion or a loose object gone
/// exposes nothing). An index whose pack is already gone
/// (`Access::RemoveOrphanIndex`) anchors nothing and may be removed
/// (2026-10-16): `git prune` removes an `.idx` left without its `.pack`
/// (git's repack unlinks an old pack's `.idx`, refused while its `.pack` is
/// there, then the `.pack`), and refusing it left an orphan index behind
/// after every history rewrite. An index beside its pack stays anchored
/// whatever that pack is, a twinned one included. Pure.
pub fn refuses(file: &StoreFile, verdict: &Verdict, access: Access) -> bool {
    if *verdict == Verdict::Clean {
        return false;
    }
    match access {
        Access::Open | Access::RenameSrc | Access::LinkSource => true,
        Access::Remove | Access::ReplaceDest | Access::Truncate => matches!(file, StoreFile::Pack { ext: PackExt::Idx, .. }),
        Access::RemoveOrphanIndex => false,
    }
}

/// Is a refusal of `access` reported as git refused in the repository (the
/// end-of-session notice, the `git-lock` read event, the arbiter's
/// `registerRepository`)? Only one that kept git from READING an
/// object-store file (an open, a rename or link source): that is what stops
/// git in the repository and what a prepared copy fixes. Keeping an index
/// anchored (a removal, a replacement, a truncate) stops nothing git needs:
/// its repack ignores the failed unlink and its prune removes the index once
/// the pack is gone, so naming the repository after a history rewrite that
/// worked told the person git was refused when it was not (2026-10-16).
/// Such a refusal is unchanged and still recorded, as its own event (a
/// refused change of the index, `events::guard_git_index_change_refusal_event`).
/// Pure.
pub fn reported(access: Access) -> bool {
    matches!(access, Access::Open | Access::RenameSrc | Access::LinkSource)
}

/// What is at an index's pack name (`pack_name_of`) in the directory an
/// unlink of the index acts on, looked up there (the guard's pinned parent,
/// so in the tracee's own view), not following a final symlink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackBeside {
    /// The name being removed is no index.
    NotAnIndex,
    /// No such name (ENOENT).
    Gone,
    /// Anything there (a pack, a twinned pack, a symlink, a directory).
    Present,
    /// The lookup failed otherwise.
    Unknown,
}

/// `PackBeside` from the lookup of an index's pack name: `Ok(())` when a
/// name is there, else its errno. Pure.
pub fn beside_of(found: Result<(), i32>) -> PackBeside {
    match found {
        Ok(()) => PackBeside::Present,
        Err(libc::ENOENT) => PackBeside::Gone,
        Err(_) => PackBeside::Unknown,
    }
}

/// The access an unlink is judged as: an index whose pack is gone is
/// `RemoveOrphanIndex`; every other name, and an index whose pack is there
/// (twinned or not: a twinned pack's inode may also be reachable under
/// another name, a hard link made before the session, which only the
/// backstop judges, by this index) or could not be looked up, is `Remove`,
/// judged as before (fail closed). Pure.
pub fn removal_access(beside: PackBeside) -> Access {
    match beside {
        PackBeside::Gone => Access::RemoveOrphanIndex,
        PackBeside::NotAnIndex | PackBeside::Present | PackBeside::Unknown => Access::Remove,
    }
}

/// The pack an index name anchors (`pack-<id>.idx` → `pack-<id>.pack`, and
/// any `<base>.idx` → `<base>.pack`, as `StoreFile::Pack` pairs them), or
/// `None` for a name that is not one component ending in `.idx`. Bytes, not
/// text: the name looked up is exactly the one the unlink removes. Pure.
pub fn pack_name_of(leaf: &[u8]) -> Option<Vec<u8>> {
    let base = leaf.strip_suffix(b".idx")?;
    (!base.is_empty() && !base.contains(&b'/') && !base.contains(&0)).then(|| [base, b".pack"].concat())
}

/// A file's identity and version, the verdict cache's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileKey {
    pub dev: u64,
    pub ino: u64,
    pub size: i64,
    pub mtime: i64,
    pub mtime_nsec: i64,
}

impl FileKey {
    pub fn of(st: &libc::stat) -> FileKey {
        FileKey { dev: st.st_dev, ino: st.st_ino, size: st.st_size, mtime: st.st_mtime, mtime_nsec: st.st_mtime_nsec }
    }
}

/// The verdict caches' bound: past it a cache starts over (a session that
/// opens more distinct object-store files than this pays the lookups again).
pub const CACHE_MAX: usize = 1 << 16;

/// A small map that starts over when full.
#[derive(Debug, Default)]
struct Bounded<V>(Mutex<HashMap<FileKey, V>>);

impl<V: Clone> Bounded<V> {
    fn get(&self, k: &FileKey) -> Option<V> {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).get(k).cloned()
    }
    fn put(&self, k: FileKey, v: V) {
        let mut m = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= CACHE_MAX {
            m.clear();
        }
        m.insert(k, v);
    }
    fn len(&self) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

fn fstat(fd: i32) -> Option<libc::stat> {
    // SAFETY: fstat into a zeroed buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    (unsafe { libc::fstat(fd, &mut st) } == 0).then_some(st)
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

/// An owned descriptor, closed on drop.
struct Fd(i32);

impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: our own descriptor.
        unsafe { libc::close(self.0) };
    }
}

fn open_at(dir: i32, name: &str, flags: i32) -> Result<Fd, i32> {
    let c = std::ffi::CString::new(name).map_err(|_| libc::EINVAL)?;
    // SAFETY: openat with a NUL-terminated name; returns a descriptor or -1.
    let fd = unsafe { libc::openat(dir, c.as_ptr(), flags | libc::O_CLOEXEC) };
    if fd < 0 { Err(errno()) } else { Ok(Fd(fd)) }
}

fn pread(fd: i32, off: u64, len: usize) -> Result<Vec<u8>, IdxError> {
    let mut buf = vec![0u8; len];
    let mut got = 0usize;
    while got < len {
        // SAFETY: pread into our own buffer.
        let n = unsafe { libc::pread(fd, buf[got..].as_mut_ptr() as *mut libc::c_void, len - got, (off + got as u64) as libc::off_t) };
        if n < 0 {
            let e = errno();
            if e == libc::EINTR {
                continue;
            }
            return Err(IdxError::Io(e));
        }
        if n == 0 {
            break;
        }
        got += n as usize;
    }
    buf.truncate(got);
    Ok(buf)
}

/// The guard's lock state for one session: the set, the verdict caches, the
/// repositories already reported. Shared by the guard's workers.
#[derive(Debug)]
pub struct GitLockGuard {
    set: LockedSet,
    /// Where each refused repository is appended once, for the launcher's
    /// notice at the end of the session (`gitLocks.noticeFile`), opened
    /// once at load (`open_notice`).
    notice_file: Option<Mutex<std::fs::File>>,
    /// An index (by identity and version) → does it list a locked id?
    idx: Bounded<bool>,
    /// A store file the tracee opened (by identity and version) → locked?
    /// Only the two firm answers are cached; UNKNOWN is asked again.
    files: Bounded<bool>,
    /// The temporary files of object content a process of the session
    /// created (an exclusive create the guard performed): path, device and
    /// inode, oldest first, at most `MADE_MAX` (past it the oldest is
    /// forgotten, and a later open of it is refused: fail closed).
    made: Mutex<VecDeque<(String, u64, u64)>>,
    reported: Mutex<HashSet<String>>,
}

/// At most this many temporary files are remembered as the session's own
/// (each lives from git's create to its link or rename, seconds at most).
pub const MADE_MAX: usize = 4096;

impl GitLockGuard {
    /// The guard for `set`; `notice_file` is opened now (`open_notice`).
    pub fn new(set: LockedSet, notice_file: Option<String>) -> GitLockGuard {
        let notice_file = notice_file.as_deref().and_then(open_notice).map(Mutex::new);
        GitLockGuard { set, notice_file, idx: Bounded::default(), files: Bounded::default(), made: Mutex::new(VecDeque::new()), reported: Mutex::new(HashSet::new()) }
    }

    pub fn is_empty(&self) -> bool {
        self.set.is_empty()
    }

    pub fn set(&self) -> &LockedSet {
        &self.set
    }

    /// Entries in the two caches (for tests).
    pub fn cached(&self) -> (usize, usize) {
        (self.idx.len(), self.files.len())
    }

    /// A file the tracee's open just CREATED (its `O_CREAT|O_EXCL` succeeded
    /// on the descriptor the guard performed it on: `seen` that descriptor's
    /// path, `key` its fstat). A temporary file of object content among
    /// them is the session's own: a later open, rename or link of it reaches
    /// only what the session wrote (`verdict_for`). Any other file: nothing.
    pub fn created(&self, seen: &str, key: &FileKey) {
        if self.set.is_empty() || classify(seen) != Some(StoreFile::Temp) {
            return;
        }
        let path = seen.strip_suffix(DELETED).unwrap_or(seen).to_string();
        let mut m = self.made.lock().unwrap_or_else(|p| p.into_inner());
        if m.len() >= MADE_MAX {
            m.pop_front();
        }
        m.push_back((path, key.dev, key.ino));
    }

    /// Did a process of the session create the temporary file at `seen`
    /// with identity `key`? Path AND identity: an inode number another
    /// writer's file reuses is not the session's, and the session's file
    /// reached under another name is a rename or link of it, judged here by
    /// the name it had.
    fn made_here(&self, seen: &str, key: &FileKey) -> bool {
        let path = seen.strip_suffix(DELETED).unwrap_or(seen);
        self.made.lock().unwrap_or_else(|p| p.into_inner()).iter().any(|(p, d, i)| p == path && *d == key.dev && *i == key.ino)
    }

    /// The verdict for the store file the tracee reached: `seen` is the path
    /// of the guard's pinned descriptor (`/proc/self/fd/N`), `key` its
    /// `fstat`. `None`: not an object-store file (the prefilter), or no
    /// lock at all. The pack's index is opened in the GUARD's view, next to
    /// the file the path names, and the file found there must be the pinned
    /// one (a directory swapped while this runs, or a name that exists only
    /// in the tracee's mount namespace, is UNKNOWN).
    pub fn verdict_for(&self, seen: &str, key: &FileKey) -> Option<(StoreFile, Verdict)> {
        if self.set.is_empty() {
            return None;
        }
        let file = classify(seen)?;
        let v = match &file {
            StoreFile::Loose { leaf } => {
                if self.set.loose_locked(leaf) { Verdict::Locked } else { Verdict::Clean }
            }
            // Never cached: the session's own file is known by path and
            // identity; every other one is refused at every open.
            StoreFile::Temp => {
                if self.made_here(seen, key) {
                    Verdict::Clean
                } else {
                    Verdict::Unknown("it is git's temporary file of objects being written by a program outside this session, with no index to check yet".into())
                }
            }
            _ => match self.files.get(key) {
                Some(true) => Verdict::Locked,
                Some(false) => Verdict::Clean,
                None => {
                    let v = self.store_verdict(seen, &file, key);
                    match v {
                        Verdict::Clean => self.files.put(*key, false),
                        Verdict::Locked => self.files.put(*key, true),
                        Verdict::Unknown(_) => {}
                    }
                    v
                }
            },
        };
        Some((file, v))
    }

    fn store_verdict(&self, seen: &str, file: &StoreFile, key: &FileKey) -> Verdict {
        let path = seen.strip_suffix(DELETED).unwrap_or(seen);
        let (dir, leaf) = split(path);
        let dir = if dir.is_empty() { "/" } else { dir };
        let dfd = match open_at(libc::AT_FDCWD, dir, libc::O_PATH | libc::O_DIRECTORY) {
            Ok(d) => d,
            Err(e) => return Verdict::Unknown(format!("its directory could not be opened (errno {e})")),
        };
        // The anchor: the pinned file IS `dir/leaf` in the guard's view.
        let name = match std::ffi::CString::new(leaf) {
            Ok(n) => n,
            Err(_) => return Verdict::Unknown("an unreadable name".into()),
        };
        // SAFETY: fstatat into a zeroed buffer, NUL-terminated name.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(dfd.0, name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 || st.st_dev != key.dev || st.st_ino != key.ino {
            return Verdict::Unknown("it is not where its path says (moved, removed, or visible only inside the agent's namespace)".into());
        }
        match file {
            StoreFile::Pack { base, ext, .. } => {
                let idx = match open_at(dfd.0, &format!("{base}.idx"), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK) {
                    Ok(f) => f,
                    Err(libc::ENOENT) => return Verdict::Unknown("its pack has no index".into()),
                    Err(e) => return Verdict::Unknown(format!("its pack index could not be opened (errno {e})")),
                };
                if *ext == PackExt::Idx {
                    // The index read is the file itself, not another put there since.
                    match fstat(idx.0) {
                        Some(s) if s.st_dev == key.dev && s.st_ino == key.ino => {}
                        _ => return Verdict::Unknown("its index changed while it was checked".into()),
                    }
                }
                self.idx_verdict(idx.0)
            }
            StoreFile::Midx { pack_dir } => self.dir_verdict(pack_dir),
            StoreFile::Loose { .. } | StoreFile::Temp => Verdict::Clean,
        }
    }

    /// Every `.idx` of a pack directory (a multi-pack index's scope):
    /// LOCKED if any lists a locked id, UNKNOWN if any gives no answer.
    fn dir_verdict(&self, pack_dir: &str) -> Verdict {
        let d = match open_at(libc::AT_FDCWD, if pack_dir.is_empty() { "/" } else { pack_dir }, libc::O_RDONLY | libc::O_DIRECTORY) {
            Ok(d) => d,
            Err(e) => return Verdict::Unknown(format!("its pack directory could not be read (errno {e})")),
        };
        let names = match std::fs::read_dir(format!("/proc/self/fd/{}", d.0)) {
            Ok(rd) => rd.flatten().filter_map(|e| e.file_name().into_string().ok()).filter(|n| n.ends_with(".idx")).collect::<Vec<_>>(),
            Err(e) => return Verdict::Unknown(format!("its pack directory could not be read ({e})")),
        };
        let mut unknown = None;
        for n in names {
            let v = match open_at(d.0, &n, libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK) {
                Ok(f) => self.idx_verdict(f.0),
                Err(e) => Verdict::Unknown(format!("{n} could not be opened (errno {e})")),
            };
            match v {
                Verdict::Locked => return Verdict::Locked,
                Verdict::Unknown(w) => unknown = Some(w),
                Verdict::Clean => {}
            }
        }
        unknown.map(Verdict::Unknown).unwrap_or(Verdict::Clean)
    }

    /// One index, by its descriptor, cached by its identity and version.
    fn idx_verdict(&self, fd: i32) -> Verdict {
        let Some(st) = fstat(fd) else { return Verdict::Unknown("its pack index could not be read".into()) };
        if st.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Verdict::Unknown("its pack index is not a regular file".into());
        }
        let key = FileKey::of(&st);
        if let Some(hit) = self.idx.get(&key) {
            return if hit { Verdict::Locked } else { Verdict::Clean };
        }
        match idx_file_holds_any(fd, st.st_size.max(0) as u64, &self.set) {
            Ok(hit) => {
                self.idx.put(key, hit);
                if hit { Verdict::Locked } else { Verdict::Clean }
            }
            Err(e) => Verdict::Unknown(e.to_string()),
        }
    }

    /// Record a refusal for the person, once per repository: appended to the
    /// notice file (`<repo>\t<why>`). `Some(repo)` the first time (the caller
    /// emits the event then), `None` after, and after `REPORT_MAX`
    /// repositories (the refusals go on; only the telling stops).
    pub fn report(&self, seen: &str, why: &str) -> Option<String> {
        let repo = repo_of(seen);
        {
            let mut r = self.reported.lock().unwrap_or_else(|p| p.into_inner());
            if r.len() >= REPORT_MAX || !r.insert(repo.clone()) {
                return None;
            }
        }
        if let Some(out) = self.notice_file.as_ref() {
            let line = format!("{}\t{}\n", notice_field(&repo), notice_field(why));
            let mut out = out.lock().unwrap_or_else(|p| p.into_inner());
            let _ = out.write_all(line.as_bytes());
        }
        Some(repo)
    }
}

/// At most this many repositories are reported in a session.
pub const REPORT_MAX: usize = 256;

/// Open the notice file ONCE, when the guard loads its policy (before any
/// program of the agent's tree runs a trapped call): created owner-only,
/// never through a symlink, and dropped unless it is a regular file with one
/// link. The guard writes as itself, outside every confinement of the
/// agent, so a notice path the agent could redirect (a symlink or a hard
/// link to a shell startup file planted in the scope dir) must never be
/// opened by name later. `None`: no notice (the refusals are unchanged).
pub fn open_notice(path: &str) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    use std::os::unix::io::AsRawFd;
    let st = fstat(f.as_raw_fd())?;
    (st.st_mode & libc::S_IFMT == libc::S_IFREG && st.st_nlink == 1).then_some(f)
}

/// A notice field on one line: tabs, newlines and other control characters,
/// and the Unicode bidi formatting characters (U+200E/F, U+202A-U+202E,
/// U+2066-U+2069: a path that reorders the line it is printed on), become
/// spaces (the launcher prints it to the person's terminal). Pure.
pub fn notice_field(s: &str) -> String {
    s.chars().map(|c| if c.is_control() || is_bidi_format(c) { ' ' } else { c }).collect()
}

/// A Unicode bidi formatting character (LRM, RLM, the embeddings and
/// overrides, the isolates). Pure.
pub fn is_bidi_format(c: char) -> bool {
    matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `idx_holds_any` over an open index file, by positioned reads.
pub fn idx_file_holds_any(fd: i32, size: u64, set: &LockedSet) -> Result<bool, IdxError> {
    let head = pread(fd, 0, 8 + 1024)?;
    let layout = idx_layout(&head, size)?;
    if layout.count > 0 {
        // The last name must be there (a truncated file is refused, not
        // half-searched).
        let last = pread(fd, layout.first + (layout.count as u64 - 1) * layout.stride, layout.format.len())?;
        if last.len() < layout.format.len() {
            return Err(IdxError::Truncated);
        }
    }
    idx_holds_any(&layout, set.names(layout.format), &|off, len| pread(fd, off, len))
}

/// The person-facing reason of a refusal (the event and the notice). Pure.
pub fn refusal_reason(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Clean => String::new(),
        Verdict::Locked => "its git history holds an object you locked, and this launch has no sanitized copy of that repository".into(),
        Verdict::Unknown(why) => format!("a lock is in force and whether this file holds a locked object could not be told ({why})"),
    }
}

/// `Format::of_len`, for tests elsewhere.
pub fn format_of_len(n: usize) -> Option<Format> {
    Format::of_len(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A version-2 index of `names` (sorted here), SHA-1 or SHA-256, with
    /// `large` large offsets; the body after the names is filler of the
    /// right size.
    fn idx_v2(names: &[Vec<u8>], h: usize, large: usize) -> Vec<u8> {
        let mut n = names.to_vec();
        n.sort();
        let mut b = IDX_MAGIC.to_vec();
        b.extend_from_slice(&2u32.to_be_bytes());
        for i in 0..256usize {
            let c = n.iter().filter(|x| (x[0] as usize) <= i).count() as u32;
            b.extend_from_slice(&c.to_be_bytes());
        }
        for x in &n {
            assert_eq!(x.len(), h);
            b.extend_from_slice(x);
        }
        b.extend(std::iter::repeat(0u8).take(n.len() * 8 + large * 8 + 2 * h));
        b
    }

    fn idx_v1(names: &[Vec<u8>]) -> Vec<u8> {
        let mut n = names.to_vec();
        n.sort();
        let mut b = Vec::new();
        for i in 0..256usize {
            let c = n.iter().filter(|x| (x[0] as usize) <= i).count() as u32;
            b.extend_from_slice(&c.to_be_bytes());
        }
        for x in &n {
            b.extend_from_slice(&[0, 0, 0, 12]);
            b.extend_from_slice(x);
        }
        b.extend(std::iter::repeat(0u8).take(40));
        b
    }

    fn name(h: usize, seed: u8) -> Vec<u8> {
        (0..h).map(|i| seed.wrapping_mul(31).wrapping_add(i as u8 * 7)).collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn holds(buf: &[u8], set: &LockedSet) -> Result<bool, IdxError> {
        let layout = idx_layout(&buf[..buf.len().min(1032)], buf.len() as u64)?;
        let read = |off: u64, len: usize| -> Result<Vec<u8>, IdxError> {
            let s = (off as usize).min(buf.len());
            Ok(buf[s..(s + len).min(buf.len())].to_vec())
        };
        idx_holds_any(&layout, set.names(layout.format), &read)
    }

    fn set_of(ids: &[String]) -> LockedSet {
        let (s, bad) = LockedSet::from_ids(ids.iter().map(String::as_str));
        assert!(bad.is_empty(), "{bad:?}");
        s
    }

    #[test]
    fn ids_parse_only_in_the_arbiters_grammar() {
        let a = "3b18e512dba79e4c8300dd08aeb37f8e728b8dad";
        assert_eq!(parse_id(&format!("sha1:{a}")).unwrap().0, Format::Sha1);
        assert_eq!(parse_id(&format!("sha256:{}", "ab".repeat(32))).unwrap().0, Format::Sha256);
        for bad in [a.to_string(), format!("sha1:{}", a.to_uppercase()), format!("sha1:{}", &a[..39]), format!("sha256:{a}"), format!("sha1:{}", "ab".repeat(32)), "sha1:".into(), format!("md5:{a}")] {
            assert!(parse_id(&bad).is_none(), "{bad}");
        }
        let (s, bad) = LockedSet::from_ids([format!("sha1:{a}").as_str(), "nope", format!("sha1:{a}").as_str()]);
        assert_eq!(s.len(), 1, "duplicates collapse");
        assert_eq!(bad, vec!["nope".to_string()]);
        assert!(s.loose_locked(&a[2..]));
        assert!(!s.loose_locked(a));
        assert!(LockedSet::default().is_empty());
        let (empty, bad) = LockedSet::from_ids(EMPTY_BLOB_IDS);
        assert!(empty.is_empty() && bad.is_empty(), "the empty blob is never locked");
    }

    #[test]
    fn the_prefilter_names_object_store_files_and_nothing_else() {
        let p = "pack-3b18e512dba79e4c8300dd08aeb37f8e728b8dad";
        for ext in ["pack", "idx", "rev", "bitmap", "mtimes"] {
            let path = format!("/r/.git/objects/pack/{p}.{ext}");
            match classify(&path) {
                Some(StoreFile::Pack { dir, base, .. }) => {
                    assert_eq!(dir, "/r/.git/objects/pack");
                    assert_eq!(base, p);
                }
                other => panic!("{path}: {other:?}"),
            }
            // A pack's own name is enough: a moved pack directory is still one.
            assert!(matches!(classify(&format!("/tmp/moved/{p}.{ext}")), Some(StoreFile::Pack { .. })), "{ext}");
        }
        // Another name counts only in objects/pack.
        assert!(matches!(classify("/r/.git/objects/pack/custom.pack"), Some(StoreFile::Pack { .. })));
        assert_eq!(classify("/home/u/src/custom.pack"), None);
        assert_eq!(classify("/home/u/src/pack-list.idx"), None, "not a pack's name, not in objects/pack");
        assert_eq!(classify("/r/.git/objects/pack/pack-abc.keep"), None);
        assert_eq!(classify("/r/.git/objects/pack/tmp_pack_Xy12Qa"), Some(StoreFile::Temp), "git's pack in progress (2026-10-17)");
        assert_eq!(classify("/r/.git/objects/3b/tmp_obj_Xy12Qa"), Some(StoreFile::Temp), "a loose object in progress");
        assert_eq!(classify("/elsewhere/tmp_pack_Xy12Qa"), Some(StoreFile::Temp), "a renamed directory changes nothing");
        assert_eq!(classify("/r/.git/objects/pack/tmp_pack_"), None, "the bare prefix is no name git makes");
        assert_eq!(classify("/r/.git/objects/pack/tmp_idx_Xy12Qa"), None, "ids only");
        assert_eq!(classify("/r/.git/objects/pack/tmp_rev_Xy12Qa"), None);
        assert_eq!(classify("/r/.git/objects/3b/tmp_object_git2_Xy12Qa"), None, "another implementation's name");
        // Multi-pack index and its layers.
        assert_eq!(classify("/r/.git/objects/pack/multi-pack-index"), Some(StoreFile::Midx { pack_dir: "/r/.git/objects/pack".into() }));
        assert_eq!(classify(&format!("/r/.git/objects/pack/multi-pack-index-{}.bitmap", "a1".repeat(20))), Some(StoreFile::Midx { pack_dir: "/r/.git/objects/pack".into() }));
        assert_eq!(classify(&format!("/r/.git/objects/pack/multi-pack-index.d/multi-pack-index-{}.midx", "a1".repeat(20))), Some(StoreFile::Midx { pack_dir: "/r/.git/objects/pack".into() }));
        assert_eq!(classify("/r/.git/objects/pack/multi-pack-index.d/multi-pack-index-chain"), None);
        // Loose objects, by the leaf alone.
        let leaf = "18e512dba79e4c8300dd08aeb37f8e728b8dad";
        assert_eq!(classify(&format!("/r/.git/objects/3b/{leaf}")), Some(StoreFile::Loose { leaf: leaf.into() }));
        assert_eq!(classify(&format!("/tmp/renamed/{leaf}")), Some(StoreFile::Loose { leaf: leaf.into() }));
        assert_eq!(classify(&format!("/r/.git/objects/3b/{}", "c".repeat(62))), Some(StoreFile::Loose { leaf: "c".repeat(62) }));
        assert_eq!(classify(&format!("/r/.git/objects/3b/{}", "C".repeat(38))), None, "git writes lowercase");
        assert_eq!(classify(&format!("/r/.git/objects/3b/{}", "c".repeat(40))), None);
        // A descriptor whose name is gone keeps its class.
        assert!(matches!(classify(&format!("/r/.git/objects/pack/{p}.pack (deleted)")), Some(StoreFile::Pack { ext: PackExt::Pack, .. })));
        for other in ["/etc/passwd", "/r/src/main.rs", "/r/.git/HEAD", "/r/.git/objects/info/alternates", "/", "", "/r/.git/objects/pack/"] {
            assert_eq!(classify(other), None, "{other}");
        }
    }

    #[test]
    fn the_repository_is_named_for_the_person() {
        assert_eq!(repo_of("/home/u/work/api/.git/objects/pack/pack-1.pack"), "/home/u/work/api");
        assert_eq!(repo_of("/srv/api.git/objects/ab/cdef"), "/srv/api.git");
        assert_eq!(repo_of("/tmp/moved/pack-1.pack"), "/tmp/moved");
        assert_eq!(repo_of("/r/.git/objects/pack/pack-1.pack (deleted)"), "/r");
    }

    #[test]
    fn a_v2_index_is_searched_for_the_locked_ids_of_its_format() {
        for h in [20usize, 32] {
            let names: Vec<Vec<u8>> = (0..300u32).map(|i| name(h, (i % 251) as u8).into_iter().enumerate().map(|(j, b)| b ^ (i >> (j % 3)) as u8).collect()).collect();
            let buf = idx_v2(&names, h, 0);
            let layout = idx_layout(&buf[..1032], buf.len() as u64).unwrap();
            assert_eq!(layout.format, format_of_len(h).unwrap());
            assert_eq!(layout.count, 300);
            let prefix = if h == 20 { "sha1" } else { "sha256" };
            for probe in [0usize, 1, 150, 299] {
                let s = set_of(&[format!("{prefix}:{}", hex(&names[probe]))]);
                assert_eq!(holds(&buf, &s), Ok(true), "h={h} probe={probe}");
            }
            let mut absent = names[7].clone();
            absent[h - 1] ^= 0x55;
            if !names.contains(&absent) {
                assert_eq!(holds(&buf, &set_of(&[format!("{prefix}:{}", hex(&absent))])), Ok(false));
            }
            // The other format's ids are never looked up in this index.
            let other = if h == 20 { format!("sha256:{}", "00".repeat(32)) } else { format!("sha1:{}", "00".repeat(20)) };
            assert_eq!(holds(&buf, &set_of(&[other])), Ok(false));
            // Large offsets change the size but not the answer.
            let big = idx_v2(&names, h, 3);
            assert_eq!(holds(&big, &set_of(&[format!("{prefix}:{}", hex(&names[5]))])), Ok(true));
        }
        // An empty index lists nothing.
        let empty = idx_v2(&[], 20, 0);
        assert_eq!(holds(&empty, &set_of(&[format!("sha1:{}", "11".repeat(20))])), Ok(false));
    }

    #[test]
    fn a_v1_index_is_searched_too() {
        let names: Vec<Vec<u8>> = (0..40u8).map(|i| name(20, i)).collect();
        let buf = idx_v1(&names);
        assert_eq!(idx_layout(&buf[..1032.min(buf.len())], buf.len() as u64).unwrap().version, 1);
        assert_eq!(holds(&buf, &set_of(&[format!("sha1:{}", hex(&names[9]))])), Ok(true));
        assert_eq!(holds(&buf, &set_of(&[format!("sha1:{}", "ee".repeat(20))])), Ok(false));
    }

    #[test]
    fn a_malformed_index_gives_no_answer() {
        let names: Vec<Vec<u8>> = (0..10u8).map(|i| name(20, i)).collect();
        let good = idx_v2(&names, 20, 0);
        let s = set_of(&[format!("sha1:{}", hex(&names[0]))]);
        assert_eq!(holds(&good[..500], &s), Err(IdxError::TooSmall));
        let mut v3 = good.clone();
        v3[7] = 3;
        assert_eq!(holds(&v3, &s), Err(IdxError::BadVersion(3)));
        let mut fan = good.clone();
        fan[8 + 4 * 200..8 + 4 * 201].copy_from_slice(&0u32.to_be_bytes()); // a dip
        fan[8 + 4 * 199..8 + 4 * 200].copy_from_slice(&5u32.to_be_bytes());
        assert_eq!(holds(&fan, &s), Err(IdxError::BadFanout));
        // A size that fits no format for its count: cut, or padded.
        assert_eq!(holds(&good[..good.len() - 3], &s), Err(IdxError::BadSize));
        let mut pad = good.clone();
        pad.extend_from_slice(&[0; 5]);
        assert_eq!(holds(&pad, &s), Err(IdxError::BadSize));
        // A count claiming more names than the file holds.
        let mut lie = good.clone();
        lie[8 + 4 * 255..8 + 4 * 256].copy_from_slice(&100_000u32.to_be_bytes());
        assert_eq!(holds(&lie, &s), Err(IdxError::BadSize));
        // A v1 index of the wrong size.
        let v1 = idx_v1(&names);
        assert_eq!(holds(&v1[..v1.len() - 1], &s), Err(IdxError::BadSize));
        // Garbage.
        assert!(holds(&[0xffu8; 2000], &s).is_err());
        // A read that comes back short mid-search.
        let layout = idx_layout(&good[..1032], good.len() as u64).unwrap();
        let short = |_: u64, _: usize| -> Result<Vec<u8>, IdxError> { Ok(vec![0; 3]) };
        assert_eq!(idx_holds_any(&layout, s.names(Format::Sha1), &short), Err(IdxError::Truncated));
    }

    #[test]
    fn the_rules_refuse_what_would_expose_or_unanchor_a_locked_object() {
        let pack = StoreFile::Pack { dir: "/r".into(), base: "pack-1".into(), ext: PackExt::Pack };
        let idx = StoreFile::Pack { dir: "/r".into(), base: "pack-1".into(), ext: PackExt::Idx };
        let loose = StoreFile::Loose { leaf: "ab".into() };
        let unknown = Verdict::Unknown("x".into());
        for a in [Access::Open, Access::RenameSrc, Access::LinkSource, Access::Remove, Access::ReplaceDest, Access::Truncate] {
            for f in [&pack, &idx, &loose] {
                assert!(!refuses(f, &Verdict::Clean, a), "a clean file is never refused");
            }
        }
        for v in [&Verdict::Locked, &unknown] {
            for f in [&pack, &idx, &loose] {
                assert!(refuses(f, v, Access::Open));
                assert!(refuses(f, v, Access::RenameSrc));
                assert!(refuses(f, v, Access::LinkSource));
            }
            for a in [Access::Remove, Access::ReplaceDest, Access::Truncate] {
                assert!(refuses(&idx, v, a), "the index anchors its pack's verdict");
                assert!(!refuses(&pack, v, a), "a pack gone exposes nothing");
                assert!(!refuses(&loose, v, a));
            }
            // 2026-10-16: an index whose pack is gone anchors nothing.
            for f in [&pack, &idx, &loose] {
                assert!(!refuses(f, v, Access::RemoveOrphanIndex));
            }
        }
    }

    #[test]
    fn an_index_is_removable_only_once_its_pack_is_gone() {
        assert_eq!(pack_name_of(b"pack-1.idx").as_deref(), Some(&b"pack-1.pack"[..]));
        assert_eq!(pack_name_of(b"tmp_idx_x.idx").as_deref(), Some(&b"tmp_idx_x.pack"[..]));
        for not_an_index in [&b"pack-1.pack"[..], b"pack-1.rev", b".idx", b"a/b.idx", b"pack-1.idx.lock", b"x\0.idx"] {
            assert_eq!(pack_name_of(not_an_index), None, "{not_an_index:?}");
        }
        // What the lookup of the pack's name found.
        assert_eq!(beside_of(Ok(())), PackBeside::Present);
        assert_eq!(beside_of(Err(libc::ENOENT)), PackBeside::Gone);
        for e in [libc::EACCES, libc::ENOTDIR, libc::ELOOP, libc::EIO, libc::ENAMETOOLONG] {
            assert_eq!(beside_of(Err(e)), PackBeside::Unknown, "{e}");
        }
        // Gone: the index anchors nothing.
        assert_eq!(removal_access(PackBeside::Gone), Access::RemoveOrphanIndex);
        // A pack there (whatever it is: the guard does not ask whether it is
        // twinned, since a twinned pack's inode may be reachable under a
        // name the twin does not cover), or no answer: as before.
        for b in [PackBeside::NotAnIndex, PackBeside::Present, PackBeside::Unknown] {
            assert_eq!(removal_access(b), Access::Remove, "{b:?}");
        }
        // The rule end to end: a locked (or unknown) index with its pack
        // beside it is refused; the same index once its pack is gone is not.
        let idx = classify("/r/.git/objects/pack/pack-1.idx").unwrap();
        for v in [Verdict::Locked, Verdict::Unknown("x".into())] {
            assert!(refuses(&idx, &v, removal_access(beside_of(Ok(())))));
            assert!(refuses(&idx, &v, removal_access(beside_of(Err(libc::EACCES)))));
            assert!(!refuses(&idx, &v, removal_access(beside_of(Err(libc::ENOENT)))));
        }
    }

    #[test]
    fn only_a_refused_read_is_reported() {
        for a in [Access::Open, Access::RenameSrc, Access::LinkSource] {
            assert!(reported(a), "{a:?}: git was kept from an object");
        }
        // Recorded as a refused change of the index instead
        // (`events::guard_git_index_change_refusal_event`), never told as git
        // refused in the repository.
        for a in [Access::Remove, Access::RemoveOrphanIndex, Access::ReplaceDest, Access::Truncate] {
            assert!(!reported(a), "{a:?}: an index kept anchored stops nothing git needs");
        }
    }

    #[test]
    fn notice_fields_stay_on_one_line() {
        assert_eq!(notice_field("/r\n\x1b[31mX\tY"), "/r  [31mX Y");
        // Bidi formatting characters never reorder the printed line.
        assert_eq!(notice_field("/h/\u{202E}vne.\u{2066}x\u{2069}\u{200F}"), "/h/ vne. x  ");
        assert_eq!(notice_field("/h/日本語/ünï"), "/h/日本語/ünï", "other text is kept");
    }

    /// A real directory: `objects/pack/pack-<h>.{pack,idx}` with an index
    /// listing `names`.
    fn store(tag: &str, names: &[Vec<u8>]) -> (std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("mandu-gitlock-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let pd = dir.join("r/.git/objects/pack");
        std::fs::create_dir_all(&pd).unwrap();
        let base = format!("pack-{}", "5a".repeat(20));
        std::fs::write(pd.join(format!("{base}.pack")), b"PACK\0\0\0\x02").unwrap();
        std::fs::write(pd.join(format!("{base}.idx")), idx_v2(names, 20, 0)).unwrap();
        (dir, format!("{}/{base}", pd.display()))
    }

    fn key_of(p: &str) -> FileKey {
        let c = std::ffi::CString::new(p).unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::stat(c.as_ptr(), &mut st) }, 0, "{p}");
        FileKey::of(&st)
    }

    #[test]
    fn the_guard_reads_the_sibling_index_and_caches_the_verdict() {
        let names: Vec<Vec<u8>> = (0..20u8).map(|i| name(20, i)).collect();
        let (dir, base) = store("verdict", &names);
        let locked = set_of(&[format!("sha1:{}", hex(&names[3]))]);
        let g = GitLockGuard::new(locked, None);
        let pack = format!("{base}.pack");
        let (f, v) = g.verdict_for(&pack, &key_of(&pack)).unwrap();
        assert!(matches!(f, StoreFile::Pack { ext: PackExt::Pack, .. }));
        assert_eq!(v, Verdict::Locked);
        assert_eq!(g.cached(), (1, 1));
        let idx = format!("{base}.idx");
        assert_eq!(g.verdict_for(&idx, &key_of(&idx)).unwrap().1, Verdict::Locked);
        assert_eq!(g.cached(), (1, 2), "the index read once");
        // Not an object-store file: no verdict at all.
        assert!(g.verdict_for("/etc/hostname", &key_of(&pack)).is_none());
        // A clean set: the same pack is clean.
        let clean = GitLockGuard::new(set_of(&[format!("sha1:{}", "ee".repeat(20))]), None);
        assert_eq!(clean.verdict_for(&pack, &key_of(&pack)).unwrap().1, Verdict::Clean);
        // A new version of the index (another size) is read again.
        std::fs::write(&idx, idx_v2(&names[4..], 20, 0)).unwrap();
        let g2 = GitLockGuard::new(set_of(&[format!("sha1:{}", hex(&names[3]))]), None);
        assert_eq!(g2.verdict_for(&pack, &key_of(&pack)).unwrap().1, Verdict::Clean);
        // The empty set checks nothing.
        assert!(GitLockGuard::new(LockedSet::default(), None).verdict_for(&pack, &key_of(&pack)).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_index_a_bad_index_or_a_moved_file_is_unknown() {
        let names: Vec<Vec<u8>> = (0..5u8).map(|i| name(20, i)).collect();
        let (dir, base) = store("unknown", &names);
        let set = set_of(&[format!("sha1:{}", hex(&names[0]))]);
        let pack = format!("{base}.pack");
        let k = key_of(&pack);
        // The identity must be the file at the path.
        let g = GitLockGuard::new(set.clone(), None);
        let other = FileKey { ino: k.ino + 12345, ..k };
        assert!(matches!(g.verdict_for(&pack, &other).unwrap().1, Verdict::Unknown(_)));
        // A bad index.
        std::fs::write(format!("{base}.idx"), b"not an index").unwrap();
        let g = GitLockGuard::new(set.clone(), None);
        assert!(matches!(g.verdict_for(&pack, &k).unwrap().1, Verdict::Unknown(ref w) if w.contains("too small")));
        assert_eq!(g.cached(), (0, 0), "UNKNOWN is never cached");
        // No index.
        std::fs::remove_file(format!("{base}.idx")).unwrap();
        let g = GitLockGuard::new(set.clone(), None);
        assert!(matches!(g.verdict_for(&pack, &k).unwrap().1, Verdict::Unknown(ref w) if w.contains("no index")));
        // A symlinked index is not followed.
        let real_idx = dir.join("elsewhere.idx");
        std::fs::write(&real_idx, idx_v2(&names, 20, 0)).unwrap();
        std::os::unix::fs::symlink(&real_idx, format!("{base}.idx")).unwrap();
        assert!(matches!(g.verdict_for(&pack, &k).unwrap().1, Verdict::Unknown(_)));
        // A descriptor whose name is gone.
        std::fs::remove_file(&pack).unwrap();
        assert!(matches!(g.verdict_for(&format!("{pack} (deleted)"), &k).unwrap().1, Verdict::Unknown(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_multi_pack_index_answers_for_every_index_beside_it() {
        let names: Vec<Vec<u8>> = (0..5u8).map(|i| name(20, i)).collect();
        let (dir, base) = store("midx", &names);
        let pd = std::path::Path::new(&base).parent().unwrap().to_path_buf();
        let midx = pd.join("multi-pack-index");
        std::fs::write(&midx, b"MIDX").unwrap();
        std::fs::write(pd.join(format!("pack-{}.idx", "6b".repeat(20))), idx_v2(&[name(20, 99)], 20, 0)).unwrap();
        let m = midx.display().to_string();
        let locked = GitLockGuard::new(set_of(&[format!("sha1:{}", hex(&names[2]))]), None);
        assert_eq!(locked.verdict_for(&m, &key_of(&m)).unwrap().1, Verdict::Locked);
        let clean = GitLockGuard::new(set_of(&[format!("sha1:{}", "ee".repeat(20))]), None);
        assert_eq!(clean.verdict_for(&m, &key_of(&m)).unwrap().1, Verdict::Clean);
        std::fs::write(pd.join(format!("pack-{}.idx", "7c".repeat(20))), b"junk").unwrap();
        let clean = GitLockGuard::new(set_of(&[format!("sha1:{}", "ee".repeat(20))]), None);
        assert!(matches!(clean.verdict_for(&m, &key_of(&m)).unwrap().1, Verdict::Unknown(_)), "one index with no answer: no answer");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_loose_object_is_judged_by_its_name() {
        let id = "3b18e512dba79e4c8300dd08aeb37f8e728b8dad";
        let g = GitLockGuard::new(set_of(&[format!("sha1:{id}")]), None);
        let k = FileKey { dev: 1, ino: 2, size: 3, mtime: 4, mtime_nsec: 5 };
        assert_eq!(g.verdict_for(&format!("/r/.git/objects/3b/{}", &id[2..]), &k).unwrap().1, Verdict::Locked);
        assert_eq!(g.verdict_for(&format!("/elsewhere/{}", &id[2..]), &k).unwrap().1, Verdict::Locked, "a renamed directory changes nothing");
        assert_eq!(g.verdict_for(&format!("/r/.git/objects/3b/{}", "0".repeat(38)), &k).unwrap().1, Verdict::Clean);
    }

    /// 2026-10-17 (plan 14 §11.1 residual): git's pack or loose object in
    /// progress has no index. One the session created is its own; any other
    /// (the person's `git gc` outside the session, mid-write) is refused at
    /// every open, rename and link, and never cached.
    #[test]
    fn a_temporary_file_of_objects_is_the_sessions_only_if_it_created_it() {
        let id = "3b18e512dba79e4c8300dd08aeb37f8e728b8dad";
        let g = GitLockGuard::new(set_of(&[format!("sha1:{id}")]), None);
        let tmp = "/r/.git/objects/pack/tmp_pack_Ab12Cd";
        let k = FileKey { dev: 7, ino: 70, size: 0, mtime: 1, mtime_nsec: 0 };
        // Another writer's file, mid-write: no answer, refused for every read.
        let (f, v) = g.verdict_for(tmp, &k).unwrap();
        assert_eq!(f, StoreFile::Temp);
        assert!(matches!(v, Verdict::Unknown(ref w) if w.contains("outside this session")), "{v:?}");
        for a in [Access::Open, Access::RenameSrc, Access::LinkSource] {
            assert!(refuses(&f, &v, a), "{a:?}");
        }
        for a in [Access::Remove, Access::ReplaceDest, Access::Truncate, Access::RemoveOrphanIndex] {
            assert!(!refuses(&f, &v, a), "{a:?}: removing it exposes nothing");
        }
        assert_eq!(g.cached(), (0, 0), "never cached");
        // The session created it: its own, at any size (git appends to it).
        g.created(tmp, &k);
        assert_eq!(g.verdict_for(tmp, &FileKey { size: 4096, mtime: 2, ..k }).unwrap().1, Verdict::Clean);
        assert_eq!(g.verdict_for(&format!("{tmp} (deleted)"), &k).unwrap().1, Verdict::Clean, "its descriptor after the unlink");
        // Another inode at that path (the name reused), or that inode number
        // at another path (reused by another writer's file): not the session's.
        assert!(matches!(g.verdict_for(tmp, &FileKey { ino: 71, ..k }).unwrap().1, Verdict::Unknown(_)));
        assert!(matches!(g.verdict_for("/r/.git/objects/3b/tmp_obj_Zz99Yy", &k).unwrap().1, Verdict::Unknown(_)));
        assert!(matches!(g.verdict_for(tmp, &FileKey { dev: 8, ..k }).unwrap().1, Verdict::Unknown(_)));
        // A create of any other file remembers nothing.
        let pack = format!("/r/.git/objects/pack/pack-{}.pack", "5a".repeat(20));
        g.created(&pack, &FileKey { ino: 72, ..k });
        g.created("/etc/x", &FileKey { ino: 73, ..k });
        assert_eq!(g.made.lock().unwrap().len(), 1);
        // A loose object in progress the same.
        let obj = "/r/.git/objects/3b/tmp_obj_Qq11Ww";
        assert!(matches!(g.verdict_for(obj, &FileKey { ino: 80, ..k }).unwrap().1, Verdict::Unknown(_)));
        g.created(obj, &FileKey { ino: 80, ..k });
        assert_eq!(g.verdict_for(obj, &FileKey { ino: 80, ..k }).unwrap().1, Verdict::Clean);
        // Bounded: past MADE_MAX the oldest is forgotten (then refused: fail closed).
        for i in 0..MADE_MAX as u64 {
            g.created(&format!("/r/.git/objects/pack/tmp_pack_n{i}"), &FileKey { ino: 1000 + i, ..k });
        }
        assert_eq!(g.made.lock().unwrap().len(), MADE_MAX);
        assert!(matches!(g.verdict_for(tmp, &k).unwrap().1, Verdict::Unknown(_)), "the oldest is forgotten");
        // No lock: nothing is checked or remembered.
        let none = GitLockGuard::new(LockedSet::default(), None);
        none.created(tmp, &k);
        assert!(none.verdict_for(tmp, &k).is_none());
        assert_eq!(none.made.lock().unwrap().len(), 0);
    }

    #[test]
    fn each_repository_is_reported_once() {
        let dir = std::env::temp_dir().join(format!("mandu-gitlock-notice-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("notice");
        let g = GitLockGuard::new(set_of(&[format!("sha1:{}", "11".repeat(20))]), Some(f.display().to_string()));
        assert_eq!(g.report("/w/a/.git/objects/pack/pack-1.pack", "why\none"), Some("/w/a".into()));
        assert_eq!(g.report("/w/a/.git/objects/pack/pack-1.idx", "again"), None);
        assert_eq!(g.report("/w/b/.git/objects/ab/cd", "b"), Some("/w/b".into()));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "/w/a\twhy one\n/w/b\tb\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600, "owner-only");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_notice_file_is_never_opened_through_a_link_the_agent_planted() {
        // The guard writes as itself, outside the agent's confinement: a
        // notice path that is a symlink or a hard link to another file (a
        // shell startup file) must not be written through.
        let dir = std::env::temp_dir().join(format!("mandu-gitlock-noticelink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("bashrc");
        std::fs::write(&victim, "original\n").unwrap();
        let sym = dir.join("sym");
        std::os::unix::fs::symlink(&victim, &sym).unwrap();
        let hard = dir.join("hard");
        std::fs::hard_link(&victim, &hard).unwrap();
        for p in [&sym, &hard] {
            assert!(open_notice(&p.display().to_string()).is_none(), "{}", p.display());
            let g = GitLockGuard::new(set_of(&[format!("sha1:{}", "11".repeat(20))]), Some(p.display().to_string()));
            assert_eq!(g.report("/w/a/.git/objects/ab/cd", "x"), Some("/w/a".into()), "the refusal is still reported (the event)");
        }
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "original\n", "nothing was written through a link");
        // A cap on how many repositories are told.
        let g = GitLockGuard::new(set_of(&[format!("sha1:{}", "11".repeat(20))]), None);
        for i in 0..REPORT_MAX {
            assert!(g.report(&format!("/w/{i}/.git/objects/ab/cd"), "x").is_some());
        }
        assert!(g.report("/w/one-more/.git/objects/ab/cd", "x").is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
