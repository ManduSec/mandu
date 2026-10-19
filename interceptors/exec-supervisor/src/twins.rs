//! twins — box-side symbol-twin detection (docs/design/integrity/symbol-twin-shell-blindness.md
//! §4.1 v2). PURE: no privileges, in the default build, unit-tested with temp dirs.
//!
//! Under the fs rung an untrusted workspace file exists in the AgentView as one
//! or more `$MDU:` symbol-token lines, so a boxed `sed -n 3p notes.md` sees
//! nothing. The proxy's v1 cut derives that fact from the model's single
//! `command` string, which cannot see what a pipeline LEAF or a post-`cd` leaf
//! actually named (each leaf reaches the box through its own shim with its own
//! argv + `--cwd`). This module looks at exactly that: the leaf's argv, joined
//! to its cwd, filtered to the AgentView root, and tested with the SAME
//! predicate the proxy uses (`interceptors/anthropic-proxy/src/twin-note.ts`
//! `twinTokens`: a regular non-symlink file ≤ 64 KiB whose every non-empty
//! line is exactly one symbol token). What it reports is a CANDIDATE LIST the
//! proxy re-verifies under its own roots — never a verdict, never file bytes.
//!
//! UTILITY-ONLY: every error path yields no candidate; the caller reports
//! best-effort and never lets a failure touch the exec.

use std::path::{Component, Path, PathBuf};

use mandu_arbiter::protocol::{ExecTwinCandidate, ExecTwinReport};
use mandu_arbiter::ArbiterClient;

/// At most this many twins per leaf are REPORTED in full (design §4.1/§4.3).
pub const TWIN_MAX_PATHS: usize = 8;
/// At most this many path-like argv words per leaf are EXAMINED (design
/// §4.1b): a glob can expand to dozens of files, and a note that listed the
/// first 8 twins and stayed silent about the rest read as "the others are
/// fine" (watch-20260918T194546 U6: `tail *.txt` over 10 files, `release.txt`
/// — the one holding the answer — fell past the cap). Beyond this bound, and
/// beyond TWIN_MAX_PATHS listed, the leaf reports a COUNT (`more`) so the note
/// can say how many named files it left out.
pub const TWIN_SCAN_MAX: usize = 64;
/// A twin larger than this is not a symbol-line file; skip without reading.
pub const TWIN_MAX_BYTES: u64 = 64 * 1024;

/// Is `line` exactly one symbol token: `$MDU:<tool>[<hex4-8>]` plus optional
/// `.field` extensions (`[a-zA-Z_][a-zA-Z0-9_[\].]*` each)? Mirrors the
/// proxy's `SYMBOL_TOKEN_LINE_RE` byte-for-byte in acceptance.
pub fn is_symbol_token_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("$MDU:") else {
        return false;
    };
    let b = rest.as_bytes();
    let mut i = 0;
    // tool: [a-zA-Z_][a-zA-Z0-9_]*
    if i >= b.len() || !(b[i].is_ascii_alphabetic() || b[i] == b'_') {
        return false;
    }
    i += 1;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
        i += 1;
    }
    // [hex4-8]
    if i >= b.len() || b[i] != b'[' {
        return false;
    }
    i += 1;
    let hex_start = i;
    while i < b.len() && (b[i].is_ascii_digit() || (b'a'..=b'f').contains(&b[i])) {
        i += 1;
    }
    let hex_len = i - hex_start;
    if !(4..=8).contains(&hex_len) || i >= b.len() || b[i] != b']' {
        return false;
    }
    i += 1;
    // (.field)*  field = [a-zA-Z_][a-zA-Z0-9_[\].]*
    while i < b.len() {
        if b[i] != b'.' {
            return false;
        }
        i += 1;
        if i >= b.len() || !(b[i].is_ascii_alphabetic() || b[i] == b'_') {
            return false;
        }
        i += 1;
        while i < b.len() && (b[i].is_ascii_alphanumeric() || matches!(b[i], b'_' | b'[' | b']' | b'.')) {
            i += 1;
        }
    }
    true
}

/// The symbol tokens of an AgentView twin, or None when the file is not a twin
/// (not a regular non-symlink file, over the size cap, empty, or any non-empty
/// line is not exactly one token). Any error → None.
pub fn twin_tokens(abs: &Path) -> Option<Vec<String>> {
    let st = std::fs::symlink_metadata(abs).ok()?;
    if !st.file_type().is_file() || st.file_type().is_symlink() {
        return None;
    }
    if st.len() == 0 || st.len() > TWIN_MAX_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(abs).ok()?;
    let mut tokens = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if !is_symbol_token_line(t) {
            return None;
        }
        tokens.push(t.to_string());
    }
    if tokens.is_empty() {
        None
    } else {
        Some(tokens)
    }
}

/// At most this many regular files under a named directory are examined.
pub const DIR_SCAN_MAX: usize = 256;

/// Does `dir` (a real, non-symlink directory) hold at least one symbolic
/// twin within the first DIR_SCAN_MAX regular files (depth-first, symlinks
/// and `.git` skipped)? Any error → false.
pub fn dir_holds_twin(dir: &Path) -> bool {
    let Ok(st) = std::fs::symlink_metadata(dir) else {
        return false;
    };
    if !st.file_type().is_dir() {
        return false;
    }
    let mut stack = vec![dir.to_path_buf()];
    let mut examined = 0usize;
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        let mut entries: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.file_name().map(|n| n == ".git").unwrap_or(false) {
                continue;
            }
            let Ok(ps) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            let ft = ps.file_type();
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                stack.push(p);
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            if examined >= DIR_SCAN_MAX {
                return false;
            }
            examined += 1;
            if twin_tokens(&p).is_some() {
                return true;
            }
        }
    }
    false
}

fn path_like(t: &str) -> bool {
    if t.is_empty() || t == "." || t == ".." || t.starts_with('-') || t.contains("://") {
        return false;
    }
    if t.contains('/') {
        return true;
    }
    // `name.ext` (1–16 ext chars), not a bare number like `3.14`
    match t.rsplit_once('.') {
        Some((stem, ext)) => {
            !stem.is_empty()
                && (1..=16).contains(&ext.len())
                && ext.bytes().all(|c| c.is_ascii_alphanumeric())
                && !t.bytes().all(|c| c.is_ascii_digit() || c == b'.')
        }
        None => false,
    }
}

/// The path-looking words of a leaf's argv (argv[0] — the program — excluded),
/// in order, de-duplicated, at most TWIN_SCAN_MAX, plus how many further
/// path-like words were NOT examined. A `--flag=path` yields its value. The
/// shell has already expanded globs/variables and stripped quotes and
/// redirections by the time argv reaches the box, so this is simpler than the
/// proxy's command-string tokenizer.
pub fn path_candidates(argv: &[String]) -> (Vec<String>, usize) {
    let mut out: Vec<String> = Vec::new();
    let mut unexamined = 0usize;
    for raw in argv.iter().skip(1) {
        let mut w: &str = raw;
        if w.starts_with('-') {
            match w.split_once('=') {
                Some((_, v)) if !v.is_empty() => w = v,
                _ => continue,
            }
        }
        if !path_like(w) || out.iter().any(|o| o == w) {
            continue;
        }
        if out.len() >= TWIN_SCAN_MAX {
            unexamined += 1;
            continue;
        }
        out.push(w.to_string());
    }
    (out, unexamined)
}

/// Lexically normalize `.` / `..` components (no symlink resolution — the twin
/// predicate rejects symlinks anyway, and the proxy re-resolves).
fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Resolve one candidate against the leaf's cwd and require it under the
/// AgentView root. Returns the absolute twin path or None.
pub fn resolve_candidate(candidate: &str, cwd: &Path, root: &Path) -> Option<PathBuf> {
    let joined = if Path::new(candidate).is_absolute() {
        PathBuf::from(candidate)
    } else {
        cwd.join(candidate)
    };
    let abs = normalize(&joined);
    let root = normalize(root);
    if abs == root || abs.starts_with(&root) {
        Some(abs)
    } else {
        None
    }
}

/// A bare argv word (`docs`, `src`) — no `/`, no `.ext` — that could name a
/// DIRECTORY the shell passed verbatim (`grep -r X docs`). Kept out of
/// `path_candidates` (whose callers expect file-ish words) and examined by
/// `detect_twins` as a directory only; `RC-[0-9]+` or `x` never resolve.
fn bare_dir_words(argv: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for w in argv.iter().skip(1) {
        // `.` / `..` — the most common spelling of "search this folder"
        // (`grep -r X .`, `find .`). `path_like` rejects them as not-a-path,
        // and they are exactly right for the directory-only leg (live watch
        // U6, 2026-09-20: a recursive grep over `.` got no note on any model).
        let dot_dir = w == "." || w == "..";
        if !dot_dir {
            if w.is_empty() || w.starts_with('-') || w.contains('/') || w.contains('.') {
                continue;
            }
            if !w.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
                continue;
            }
        }
        if out.iter().any(|o| o == w) {
            continue;
        }
        out.push(w.clone());
        if out.len() >= TWIN_SCAN_MAX {
            break;
        }
    }
    out
}

/// The symbolic twins a leaf named: candidates → resolved under the root →
/// predicate; the first TWIN_MAX_PATHS in full, the rest as a COUNT (`more`
/// = symbolic twins past the cap + path-like words past the scan bound).
/// Bare words are tried as directories after the path-like candidates.
/// Never panics; any error is a skipped candidate.
pub fn detect_twins(argv: &[String], cwd: &Path, root: &Path) -> (Vec<ExecTwinCandidate>, usize) {
    let mut out = Vec::new();
    let (mut cands, unexamined) = path_candidates(argv);
    cands.extend(bare_dir_words(argv));
    let mut more = unexamined;
    for cand in cands {
        let Some(abs) = resolve_candidate(&cand, cwd, root) else {
            continue;
        };
        // A DIRECTORY under the root (`grep -r DIR`, `find DIR`) is reported
        // as a candidate too when it holds at least one symbolic twin; the
        // proxy re-walks it and writes the directory form of the note
        // (counts only — no filename the model did not type is ever carried,
        // here or there). Bounded: DIR_SCAN_MAX regular files examined.
        if twin_tokens(&abs).is_none() && !dir_holds_twin(&abs) {
            continue;
        }
        let Some(abs_s) = abs.to_str() else {
            continue;
        };
        if out.len() >= TWIN_MAX_PATHS {
            more += 1;
            continue;
        }
        out.push(ExecTwinCandidate { as_typed: cand, abs: abs_s.to_string() });
    }
    (out, more)
}

/// Detect + report, BEST-EFFORT and off the security path: `None` cwd or
/// root, no candidates, or an arbiter error all return 0 and change nothing
/// about the exec. Returns how many candidates the arbiter recorded.
pub fn report_twins(
    client: &mut ArbiterClient,
    argv: &[String],
    cwd: Option<&str>,
    agent_view_root: Option<&str>,
) -> u32 {
    let (Some(cwd), Some(root)) = (cwd, agent_view_root) else {
        return 0;
    };
    if cwd.is_empty() || root.is_empty() {
        return 0;
    }
    let (twins, more) = detect_twins(argv, Path::new(cwd), Path::new(root));
    if twins.is_empty() {
        return 0;
    }
    let report = ExecTwinReport {
        argv: argv.to_vec(),
        cwd: Some(cwd.to_string()),
        twins,
        more: u32::try_from(more).unwrap_or(u32::MAX),
    };
    client.report_exec_twins(&report).map(|r| r.recorded).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mandu_arbiter::mock::{op_handler, MockArbiter};
    use std::fs;
    use std::sync::{Arc, Mutex};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "mandu-twins-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn symbol_token_line_accepts_the_canonical_shapes_and_nothing_else() {
        assert!(is_symbol_token_line("$MDU:Read[2d3e].notes.md"));
        assert!(is_symbol_token_line("$MDU:Read[d3bd].__mdu_field_x"));
        assert!(is_symbol_token_line("$MDU:Bash[0123abcd]"));
        assert!(is_symbol_token_line("$MDU:Read[2d3e].__mdu_split[3]"));
        assert!(!is_symbol_token_line("$MDU:Read[XXXX].notes.md"), "non-hex hash");
        assert!(!is_symbol_token_line("$MDU:Read[2d3]"), "hash too short");
        assert!(!is_symbol_token_line("$MDU:Read[2d3e].notes.md trailing"));
        assert!(!is_symbol_token_line("text $MDU:Read[2d3e]"));
        assert!(!is_symbol_token_line("nothing to see here."));
        assert!(!is_symbol_token_line("$MDU:[2d3e]"));
    }

    #[test]
    fn path_candidates_skip_program_flags_and_numbers_but_take_flag_values() {
        let argv: Vec<String> = ["sed", "-n", "3p", "notes.md", "--file=extra.txt", "3.14", "docs/a", "-"]
            .iter().map(|s| s.to_string()).collect();
        assert_eq!(path_candidates(&argv), (vec!["notes.md".to_string(), "extra.txt".into(), "docs/a".into()], 0));
        // the scan bound: 70 path words → 64 examined, 6 counted as unexamined
        let many: Vec<String> = std::iter::once("cat".to_string())
            .chain((0..70).map(|i| format!("f{i}.md"))).collect();
        let (c, unexamined) = path_candidates(&many);
        assert_eq!((c.len(), unexamined), (TWIN_SCAN_MAX, 6));
        assert!(path_candidates(&["cat".to_string()]).0.is_empty());
    }

    #[test]
    fn twin_predicate_over_real_files() {
        let d = tmp("pred");
        let twin = d.join("notes.md");
        fs::write(&twin, "$MDU:Read[2d3e].notes.md\n").unwrap();
        assert_eq!(twin_tokens(&twin), Some(vec!["$MDU:Read[2d3e].notes.md".to_string()]));
        let split = d.join("edited.md");
        fs::write(&split, "$MDU:Read[2d3e].__mdu_split[0]\n\n$MDU:Read[2d3e].__mdu_split[1]\n").unwrap();
        assert_eq!(twin_tokens(&split).map(|t| t.len()), Some(2));
        let plain = d.join("plain.md");
        fs::write(&plain, "# hello\n").unwrap();
        assert_eq!(twin_tokens(&plain), None);
        let empty = d.join("empty.md");
        fs::write(&empty, "").unwrap();
        assert_eq!(twin_tokens(&empty), None);
        let link = d.join("link.md");
        std::os::unix::fs::symlink(&twin, &link).unwrap();
        assert_eq!(twin_tokens(&link), None, "symlinks are never twins");
        assert_eq!(twin_tokens(&d), None, "a directory is not a twin");
        assert_eq!(twin_tokens(&d.join("missing.md")), None);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn detect_twins_joins_cwd_and_stays_under_the_root() {
        let root = tmp("root");
        let docs = root.join("docs");
        fs::create_dir_all(&docs).unwrap();
        fs::write(docs.join("release-notes-alpha.md"), "$MDU:Read[d3bd].__mdu_field_0\n").unwrap();
        fs::write(root.join("notes.md"), "$MDU:Read[2d3e].notes.md\n").unwrap();
        fs::write(root.join("own.txt"), "agent-written\n").unwrap();
        let argv = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();

        // the post-cd leaf: relative to cwd=docs
        let (got, more) = detect_twins(&argv(&["sed", "-n", "3p", "release-notes-alpha.md"]), &docs, &root);
        assert_eq!((got, more), (vec![ExecTwinCandidate {
            as_typed: "release-notes-alpha.md".into(),
            abs: docs.join("release-notes-alpha.md").to_str().unwrap().to_string(),
        }], 0));
        // `..` climbs inside the root; a non-twin sibling is dropped (and not counted)
        let (got, more) = detect_twins(&argv(&["cat", "../notes.md", "../own.txt"]), &docs, &root);
        assert_eq!((got.len(), more), (1, 0));
        assert_eq!(got[0].as_typed, "../notes.md");
        // an absolute path outside the root never reports, even if it is a twin-shaped file
        let outside = tmp("outside");
        fs::write(outside.join("t.md"), "$MDU:Read[2d3e].t\n").unwrap();
        let abs = outside.join("t.md").to_str().unwrap().to_string();
        assert!(detect_twins(&argv(&["cat", &abs]), &root, &root).0.is_empty());
        // `..` escaping the root is dropped
        assert!(detect_twins(&argv(&["cat", "../../etc/passwd"]), &docs, &root).0.is_empty());
        // a DIRECTORY under the root that holds twins is a candidate (`grep -r docs`);
        // an empty/non-twin directory is not
        let (got, _) = detect_twins(&argv(&["grep", "-rhoE", "RC-[0-9]+", "docs", "--include=*.md"]), &root, &root);
        assert_eq!(got.iter().map(|c| c.as_typed.as_str()).collect::<Vec<_>>(), vec!["docs"], "the dir itself, never its file names");
        fs::create_dir_all(root.join("empty")).unwrap();
        assert!(detect_twins(&argv(&["grep", "-r", "x", "empty"]), &root, &root).0.is_empty());
        // `.` / `..` are directory words too (live watch U6: `grep -r X .`);
        // `..` from docs is the root, from the root it escapes and is dropped
        let (got, _) = detect_twins(&argv(&["grep", "-rEo", "RC-[0-9]+", "--include=*.txt", "."]), &root, &root);
        assert_eq!(got.iter().map(|c| (c.as_typed.as_str(), c.abs.as_str())).collect::<Vec<_>>(), vec![(".", root.to_str().unwrap())]);
        let (got, _) = detect_twins(&argv(&["grep", "-r", "x", ".."]), &docs, &root);
        assert_eq!(got.iter().map(|c| c.abs.as_str()).collect::<Vec<_>>(), vec![root.to_str().unwrap()]);
        assert!(detect_twins(&argv(&["grep", "-r", "x", ".."]), &root, &root).0.is_empty());
        assert!(detect_twins(&argv(&["grep", "-r", "x", "."]), &root.join("empty"), &root).0.is_empty());
        assert!(dir_holds_twin(&docs) && !dir_holds_twin(&root.join("empty")) && !dir_holds_twin(&root.join("notes.md")));
        // the U6 shape: a glob over 10 twins lists 8 and COUNTS the other 2
        let mut ten: Vec<&str> = vec!["tail", "-n", "+1"];
        let names: Vec<String> = (0..10).map(|i| format!("g{i}.txt")).collect();
        for n in &names {
            fs::write(root.join(n), format!("$MDU:Read[{:04x}].x\n", 0x1000 + names.iter().position(|x| x == n).unwrap())).unwrap();
            ten.push(n);
        }
        let (got, more) = detect_twins(&argv(&ten), &root, &root);
        assert_eq!((got.len(), more), (TWIN_MAX_PATHS, 2));
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&outside);
    }

    #[test]
    fn report_twins_sends_the_nested_report_and_is_silent_without_a_view_or_twins() {
        let root = tmp("report");
        fs::write(root.join("notes.md"), "$MDU:Read[2d3e].notes.md\n").unwrap();
        let seen: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let arbiter = MockArbiter::start(op_handler(move |op, req| match op {
            "reportExecTwins" => {
                seen2.lock().unwrap().push(req.clone());
                Ok(serde_json::json!({ "recorded": 1 }))
            }
            _ => Err("unexpected op".into()),
        }));
        let mut c = ArbiterClient::new(&arbiter.socket_path);
        let argv: Vec<String> = ["cat", "notes.md"].iter().map(|s| s.to_string()).collect();
        let root_s = root.to_str().unwrap();
        assert_eq!(report_twins(&mut c, &argv, Some(root_s), Some(root_s)), 1);
        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 1);
        let rep = &got[0]["report"];
        assert_eq!(rep["argv"], serde_json::json!(["cat", "notes.md"]));
        assert_eq!(rep["cwd"], serde_json::json!(root_s));
        assert_eq!(rep["twins"][0]["asTyped"], "notes.md");
        assert_eq!(rep["twins"][0]["abs"], root.join("notes.md").to_str().unwrap());
        assert!(rep.get("more").is_none(), "a zero `more` is not serialized");
        drop(got);
        // no view pair → nothing sent; a non-twin → nothing sent
        assert_eq!(report_twins(&mut c, &argv, Some(root_s), None), 0);
        let plain: Vec<String> = ["cat", "missing.md"].iter().map(|s| s.to_string()).collect();
        assert_eq!(report_twins(&mut c, &plain, Some(root_s), Some(root_s)), 0);
        assert_eq!(seen.lock().unwrap().len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    /// A wedged arbiter costs the twin report its report deadline (2 s at
    /// most, under any client deadline), then nothing: 0, the exec goes on.
    #[test]
    fn a_wedged_arbiter_costs_the_report_its_deadline_only() {
        let root = tmp("wedged");
        fs::write(root.join("notes.md"), "$MDU:Read[2d3e].notes.md\n").unwrap();
        let arbiter = mandu_arbiter::mock::StallingArbiter::wedged();
        let mut c = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(std::time::Duration::from_secs(30)));
        let argv: Vec<String> = ["cat", "notes.md"].iter().map(|s| s.to_string()).collect();
        let root_s = root.to_str().unwrap();
        let t0 = std::time::Instant::now();
        assert_eq!(report_twins(&mut c, &argv, Some(root_s), Some(root_s)), 0);
        let took = t0.elapsed();
        assert!(took < mandu_arbiter::client::REPORT_IO_TIMEOUT * 3, "the report waited {took:?}");
        assert_eq!(arbiter.asked_after("reportExecTwins", 1), 1);
        let _ = fs::remove_dir_all(&root);
    }
}
