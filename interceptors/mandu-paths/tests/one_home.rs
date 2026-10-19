//! The generated table names the one Mandu home (on-disk-layout.md §3, §7
//! phase 3c), and the resolvers are pure. The generated cases inside
//! src/lib.rs prove this copy agrees with scripts/paths/mandu-paths.mjs; this
//! file pins what the table says, so a layout change shows up here on purpose.

use mandu_paths::{base, entry, join, names, normalize, path, Kind, PATHS};

fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
    move |k: &str| pairs.iter().find(|(key, _)| *key == k).map(|(_, v)| v.to_string())
}

fn at(name: &str, pairs: &'static [(&'static str, &'static str)], home: &str) -> String {
    path(name, &env_of(pairs), home).expect("known entry")
}

#[test]
fn home_only_gives_the_one_home() {
    let h = "/home/u";
    assert_eq!(at(names::MANDU_HOME, &[], h), "/home/u/.mandu");
    assert_eq!(at(names::CONFIG_TOML, &[], h), "/home/u/.mandu/config.toml");
    assert_eq!(at(names::POLICY, &[], h), "/home/u/.mandu/policy.yaml");
    assert_eq!(at(names::SYMBOL_DB, &[], h), "/home/u/.mandu/state/mandu.db");
    assert_eq!(at(names::VIEW_STATE, &[], h), "/home/u/.mandu/state");
    assert_eq!(at(names::WORKSPACES, &[], h), "/home/u/.mandu/state/workspaces");
    assert_eq!(at(names::EVENTS, &[], h), "/home/u/.mandu/events");
    assert_eq!(at(names::EVENTS_TEST, &[], h), "/home/u/.mandu/events/test");
    assert_eq!(at(names::CI_RUNS, &[], h), "/home/u/.mandu/runs/ci");
    assert_eq!(at(names::REPLAY_DRILL_RUNS, &[], h), "/home/u/.mandu/runs/drills/replay");
    assert_eq!(at(names::DRILL_BASELINES, &[], h), "/home/u/.mandu/runs/drills/baselines");
    assert_eq!(at(names::DOCKER_E2E_HOME, &[], h), "/home/u/.mandu/dev/docker-e2e-home");
    assert_eq!(at(names::OBJECT_TWINS, &[], h), "/home/u/.mandu/cache/object-twins");
    assert_eq!(at(names::EXEC_BOX_CACHE, &[], h), "/home/u/.local/share/mandu/exec-box", "outside the home: the agent runs it");
    assert_eq!(at(names::RUNTIME_DIR, &[], h), "/tmp/mandu");
    assert_eq!(at(names::INSTALL_PREFIX, &[], h), "/home/u/.local/share/mandu");
}

#[test]
fn mandu_home_moves_everything_and_overrides_are_verbatim() {
    let env: &[(&str, &str)] = &[("MANDU_HOME", "/m"), ("XDG_STATE_HOME", "/s"), ("XDG_RUNTIME_DIR", "/run/user/1000")];
    assert_eq!(at(names::EVENTS, env, "/h"), "/m/events");
    assert_eq!(at(names::WORKSPACES, env, "/h"), "/m/state/workspaces");
    assert_eq!(at(names::EXEC_BOX_CACHE, env, "/h"), "/h/.local/share/mandu/exec-box", "the install prefix does not follow MANDU_HOME");
    assert_eq!(at(names::RUNTIME_DIR, env, "/h"), "/run/user/1000/mandu", "the runtime dir stays outside the home");
    assert_eq!(at(names::EVENTS, &[("XDG_STATE_HOME", "/s")], "/h"), "/h/.mandu/events", "XDG roots move nothing");
    assert_eq!(at(names::RUNTIME_DIR, &[("MANDU_RUNTIME_DIR", "/pinned/")], "/h"), "/pinned/", "an override is verbatim");
    assert_eq!(at(names::EVENTS, &[("MANDU_HOME", "")], "/h"), "/h/.mandu/events", "empty counts as unset");
    // Phase 4 (on-disk-layout.md §9 1): nothing in the home has its own override.
    assert_eq!(at(names::EVENTS, &[("MANDU_EVENT_DIR", "/e")], "/h"), "/h/.mandu/events", "MANDU_EVENT_DIR is retired");
    assert_eq!(at(names::WORKSPACES, &[("MANDU_VIEW_STATE", "/v")], "/h"), "/h/.mandu/state/workspaces", "MANDU_VIEW_STATE is retired");
}

#[test]
fn unknown_names_resolve_to_none() {
    let none = |_: &str| None;
    assert_eq!(path("no-such-path", &none, "/h"), None);
    assert_eq!(base("no-such-base", &none, "/h"), None);
}

#[test]
fn the_table_is_sound() {
    for e in PATHS {
        assert!(!e.rel.starts_with('/'), "{}: rel is relative", e.name);
        if let Some(parent) = entry(e.base) {
            assert_eq!(parent.kind, Kind::Dir, "{}: parent is a dir", e.name);
        }
        if !e.agent_readable {
            assert!(e.mode.is_some_and(|m| m & 0o077 == 0), "{}: an agent-denied store is owner-only", e.name);
        }
    }
}

#[test]
fn join_matches_node() {
    assert_eq!(join("/home/u/", ""), "/home/u/");
    assert_eq!(join("/", ""), "/");
    assert_eq!(join("/a//b/", "c"), "/a/b/c");
    assert_eq!(join("", ""), ".");
    assert_eq!(normalize("/a/../../b"), "/b");
    assert_eq!(normalize("a/../../b"), "../b");
    assert_eq!(normalize("./"), "./");
}
