//! Following an arbiter restart (arbiter-human-plane.md §5.1): the adoption
//! checks, a real re-learn over sockets, no retry of a written request, and
//! the backoff. Unprivileged, default features.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::client::{acceptable_human_sock, rediscover_human, ArbiterClient, Rediscovery, REDISCOVER_MIN};
use crate::mock::{op_handler, MockArbiter};
use crate::protocol::HelloResult;

fn unique(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!("mandu-rd-{tag}-{}-{}.sock", std::process::id(), N.fetch_add(1, Ordering::Relaxed)))
}

fn hello(human: Option<&str>, channel: &str, id: &str) -> HelloResult {
    HelloResult { human_sock: human.map(String::from), channel: Some(channel.into()), instance_id: Some(id.into()) }
}

#[test]
fn acceptable_human_sock_is_absolute_dot_sock_in_the_stale_dir_and_never_the_data_socket() {
    let stale = Path::new("/run/user/1/mandu/human/i1.sock");
    let data = Path::new("/run/user/1/mandu/current/arbiter.sock");
    assert!(acceptable_human_sock("/run/user/1/mandu/human/i2.sock", stale, data));
    assert!(!acceptable_human_sock("/run/user/1/mandu/human/../current/arbiter.sock", stale, data));
    assert!(!acceptable_human_sock("/run/user/1/mandu/current/arbiter.sock", stale, data));
    assert!(!acceptable_human_sock("/tmp/x/i2.sock", stale, data));
    assert!(!acceptable_human_sock("human/i2.sock", stale, data));
    assert!(!acceptable_human_sock("/run/user/1/mandu/human/i2", stale, data));
    assert!(!acceptable_human_sock("", stale, data));
    let same = Path::new("/run/user/1/mandu/human/i1.sock");
    assert!(!acceptable_human_sock("/run/user/1/mandu/human/i1.sock", same, same), "the data socket in the human dir is still the data socket");
    let long = format!("/run/user/1/mandu/human/{}.sock", "x".repeat(200));
    assert!(!acceptable_human_sock(&long, stale, data), "too long to dial as written");
    assert!(!acceptable_human_sock("/run/user/1/mandu/human/i2.sock", Path::new("human/i1.sock"), data));
}

#[test]
fn rediscover_human_adopts_only_the_human_channel_of_the_same_instance() {
    let data = Path::new("/r/current/arbiter.sock");
    let stale = Path::new("/r/human/i1.sock");
    let new = "/r/human/i2.sock";
    let answer = |d: HelloResult, c: Option<HelloResult>| {
        move |p: &Path| if p == Path::new("/r/current/arbiter.sock") { Some(d.clone()) } else { c.clone() }
    };
    assert_eq!(rediscover_human(data, stale, answer(hello(Some(new), "data", "i2"), Some(hello(None, "human", "i2")))), Some(PathBuf::from(new)));
    assert_eq!(rediscover_human(data, stale, answer(hello(Some(new), "data", "i2"), Some(hello(None, "data", "i2")))), None, "answers as the data channel");
    assert_eq!(rediscover_human(data, stale, answer(hello(Some(new), "data", "i2"), Some(hello(None, "human", "i3")))), None, "another instance");
    assert_eq!(rediscover_human(data, stale, answer(hello(Some(new), "data", "i2"), None)), None, "the candidate does not answer");
    assert_eq!(rediscover_human(data, stale, answer(hello(Some("/r/current/arbiter.sock"), "data", "i2"), Some(hello(None, "human", "i2")))), None, "the data socket named");
    assert_eq!(rediscover_human(data, stale, answer(hello(Some("/elsewhere/i2.sock"), "data", "i2"), Some(hello(None, "human", "i2")))), None, "outside the human dir");
    assert_eq!(rediscover_human(data, stale, answer(hello(None, "data", "i2"), Some(hello(None, "human", "i2")))), None, "no human socket named");
    assert_eq!(rediscover_human(data, stale, |_p: &Path| None), None, "the data socket does not answer");
    // An older arbiter names no instance id: the channel check still holds.
    let old = |p: &Path| {
        if p == data {
            Some(HelloResult { human_sock: Some(new.into()), ..Default::default() })
        } else {
            Some(HelloResult { channel: Some("human".into()), ..Default::default() })
        }
    };
    assert_eq!(rediscover_human(data, stale, old), Some(PathBuf::from(new)));
}

/// A restarted arbiter: the human socket the client was given is gone, the
/// data socket names a new one in the same directory. The client re-learns
/// it, the data socket sees only `hello`, and a client built later starts at
/// the learned path.
#[test]
fn a_human_plane_client_relearns_a_restarted_arbiters_human_socket() {
    let human_b = MockArbiter::start(op_handler(|op, req| match op {
        "hello" => Ok(serde_json::json!({ "channel": "human", "instanceId": "i2" })),
        "desymbolize" => Ok(serde_json::json!({ "text": req["text"].as_str().unwrap_or("").replace("$MDU:x[a1b2]", "VALUE") })),
        other => Err(format!("unexpected {other}")),
    }));
    let b_path = human_b.socket_path.to_string_lossy().to_string();
    let data = MockArbiter::start(op_handler(move |op, _req| match op {
        "hello" => Ok(serde_json::json!({ "humanSock": b_path.clone(), "channel": "data", "instanceId": "i2" })),
        "desymbolize" => Ok(serde_json::json!({ "text": "DATA-SOCKET-ASKED" })),
        other => Err(format!("unexpected {other}")),
    }));
    let stale = unique("gone");
    assert_eq!(stale.parent(), human_b.socket_path.parent(), "the mocks and the stale path share the temp dir");
    let mut c = ArbiterClient::human_plane(&stale, Some(&data.socket_path));
    assert_eq!(c.desymbolize("k=$MDU:x[a1b2]").unwrap().text, "k=VALUE");
    assert_eq!(c.socket_path(), human_b.socket_path.as_path());
    assert_eq!(c.rediscoveries(), 1);
    assert_eq!(data.request_count(), 1, "the data socket answered one hello and nothing else");
    drop(c); // the mock serves one connection at a time
    let mut later = ArbiterClient::human_plane(&stale, Some(&data.socket_path));
    assert_eq!(later.socket_path(), human_b.socket_path.as_path(), "a client built later starts at the learned path");
    assert_eq!(later.desymbolize("$MDU:x[a1b2]").unwrap().text, "VALUE");
    assert_eq!(later.rediscoveries(), 0);
    assert_eq!(data.request_count(), 1);
    // Without a data socket: a plain client, stuck on the dead path.
    let mut plain = ArbiterClient::human_plane(unique("gone-plain"), None);
    assert!(plain.desymbolize("$MDU:x[a1b2]").is_err());
}

/// An old arbiter at a fresh path: answers one ping, then (when
/// `read_second`) reads one more request without answering it, then dies
/// and takes its socket file with it.
fn dying_arbiter(read_second: bool) -> (PathBuf, std::thread::JoinHandle<()>) {
    let a_path = unique("dying");
    let listener = UnixListener::bind(&a_path).unwrap();
    let a_for_thread = a_path.clone();
    let h = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let id = serde_json::from_str::<Value>(line.trim()).unwrap()["id"].clone();
        let reply = serde_json::json!({ "id": id, "ok": true, "result": { "pong": true, "protocolVersion": 1 } });
        w.write_all(format!("{reply}\n").as_bytes()).unwrap();
        if read_second {
            line.clear();
            let _ = r.read_line(&mut line);
        }
        drop(listener);
        let _ = std::fs::remove_file(&a_for_thread);
    });
    (a_path, h)
}

/// The old arbiter answers one request and is gone before the next is
/// written: that write fails with EPIPE, so nothing was delivered, and the
/// request goes once more on a fresh dial, which re-learns the path.
#[test]
fn a_write_the_dead_peer_never_received_is_sent_on_a_fresh_dial() {
    let (a_path, old) = dying_arbiter(false);
    let new = MockArbiter::start(op_handler(|op, _| match op {
        "ping" => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
        other => Err(format!("unexpected {other}")),
    }));
    let to = new.socket_path.clone();
    let mut c = ArbiterClient::with_rediscovery(&a_path, Arc::new(move |_stale: &Path| Rediscovery::Found(to.clone())));
    assert!(c.ping().unwrap().pong);
    old.join().unwrap();
    assert!(c.ping().unwrap().pong, "the undelivered request reached the new arbiter");
    assert_eq!(new.request_count(), 1, "exactly once");
    assert_eq!(c.rediscoveries(), 1);
}

/// The old arbiter READS the next request and dies without answering. That
/// request was delivered, so it is NOT retried on the new socket (some
/// human-plane ops spend a verdict); the one after it dials and re-learns.
#[test]
fn a_request_written_into_a_dying_connection_is_not_retried() {
    let (a_path, old) = dying_arbiter(true);
    let new = MockArbiter::start(op_handler(|op, _| match op {
        "ping" => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
        other => Err(format!("unexpected {other}")),
    }));
    let to = new.socket_path.clone();
    let asked = Arc::new(AtomicU64::new(0));
    let asked2 = asked.clone();
    let mut c = ArbiterClient::with_rediscovery(
        &a_path,
        Arc::new(move |_stale: &Path| {
            asked2.fetch_add(1, Ordering::Relaxed);
            Rediscovery::Found(to.clone())
        }),
    );
    assert!(c.ping().unwrap().pong);
    assert!(c.ping().is_err(), "the request the old arbiter read and never answered fails");
    old.join().unwrap();
    assert_eq!(new.request_count(), 0, "and is not retried on the new socket");
    assert_eq!(asked.load(Ordering::Relaxed), 0);
    assert!(c.ping().unwrap().pong, "the next request dials and re-learns");
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    assert_eq!(new.request_count(), 1);
}

/// While the arbiter is down its data socket does not answer either: each
/// dial asks again (one failed connect), and no backoff window grows, so the
/// first dial after the arbiter is back re-learns at once.
#[test]
fn an_unreachable_arbiter_grows_no_backoff() {
    let asked = Arc::new(AtomicU64::new(0));
    let asked2 = asked.clone();
    let up = Arc::new(std::sync::Mutex::new(None::<PathBuf>));
    let up2 = up.clone();
    let mut c = ArbiterClient::with_rediscovery(
        unique("down"),
        Arc::new(move |_stale: &Path| {
            asked2.fetch_add(1, Ordering::Relaxed);
            match up2.lock().unwrap().clone() {
                Some(p) => Rediscovery::Found(p),
                None => Rediscovery::Unreachable,
            }
        }),
    );
    for _ in 0..5 {
        assert!(c.ping().is_err());
    }
    assert_eq!(asked.load(Ordering::Relaxed), 5, "asked on every dial while down");
    let back = MockArbiter::start(op_handler(|op, _| match op {
        "ping" => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
        other => Err(format!("unexpected {other}")),
    }));
    *up.lock().unwrap() = Some(back.socket_path.clone());
    assert!(c.ping().unwrap().pong, "the first dial after the arbiter is back re-learns");
    drop(c); // before the mock: its drop joins the connection it serves
}

/// The real socket rediscovery: a data socket with nothing listening is
/// `Unreachable`, not `Nothing`.
#[test]
fn a_human_plane_client_with_its_arbiter_down_keeps_asking() {
    let data = unique("data-down");
    let mut c = ArbiterClient::human_plane(unique("human-down"), Some(&data));
    for _ in 0..3 {
        assert!(c.ping().is_err());
    }
    let human = MockArbiter::start(op_handler(|op, _| match op {
        "hello" => Ok(serde_json::json!({ "channel": "human", "instanceId": "i9" })),
        "ping" => Ok(serde_json::json!({ "pong": true, "protocolVersion": 1 })),
        other => Err(format!("unexpected {other}")),
    }));
    let hp = human.socket_path.to_string_lossy().to_string();
    // The data socket comes back at its old path (as `current/arbiter.sock` does).
    let listener = UnixListener::bind(&data).unwrap();
    let srv = std::thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        let id = serde_json::from_str::<Value>(line.trim()).unwrap()["id"].clone();
        let reply = serde_json::json!({ "id": id, "ok": true, "result": { "humanSock": hp, "channel": "data", "instanceId": "i9" } });
        w.write_all(format!("{reply}\n").as_bytes()).unwrap();
    });
    assert!(c.ping().unwrap().pong, "re-learned at once, no backoff window from the downtime");
    drop(c); // before the mock: it serves one connection at a time, and its drop joins
    srv.join().unwrap();
    let _ = std::fs::remove_file(&data);
}

#[test]
fn rediscovery_backs_off_while_it_finds_nothing() {
    let asked = Arc::new(AtomicU64::new(0));
    let asked2 = asked.clone();
    let mut c = ArbiterClient::with_rediscovery(
        unique("nothing"),
        Arc::new(move |_stale: &Path| {
            asked2.fetch_add(1, Ordering::Relaxed);
            Rediscovery::Nothing
        }),
    );
    for _ in 0..5 {
        assert!(c.ping().is_err());
    }
    assert_eq!(asked.load(Ordering::Relaxed), 1, "one rediscovery inside the first window");
    std::thread::sleep(REDISCOVER_MIN + Duration::from_millis(50));
    assert!(c.ping().is_err());
    assert_eq!(asked.load(Ordering::Relaxed), 2, "the window passed: asked again");
    assert!(c.ping().is_err());
    assert_eq!(asked.load(Ordering::Relaxed), 2, "the next window is longer");
}
