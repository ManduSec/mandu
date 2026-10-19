//! A wedged arbiter (mandu.md §2.x): every request of the client gives up at
//! its deadline with an error of its own kind, and the connection it gave up
//! on is never used again. Against fake arbiters that accept and never
//! answer, answer late, trickle an answer, or never accept at all.
//! Unprivileged, default features.

use std::io::Write;
use std::os::unix::net::UnixListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::client::{ArbiterClient, ArbiterError, DEFAULT_IO_TIMEOUT, REPORT_IO_TIMEOUT};
use crate::event::{self, ManduEvent};
use crate::mock::{op_stall, Stall, StallingArbiter};

const SHORT: Duration = Duration::from_millis(200);

fn pong() -> Stall {
    Stall::Answer(Ok(json!({ "pong": true, "protocolVersion": 1 })))
}

fn assert_timeout(r: Result<impl std::fmt::Debug, ArbiterError>, op: &str, after: Duration) {
    match r {
        Err(e @ ArbiterError::Timeout { .. }) => {
            assert!(e.is_timeout());
            let ArbiterError::Timeout { op: got_op, after: got_after } = &e else { unreachable!() };
            assert_eq!(got_op, op);
            assert_eq!(*got_after, after);
            let msg = e.to_string();
            assert!(msg.contains(op) && msg.contains("timed out") && msg.contains("fail closed"), "{msg}");
        }
        other => panic!("expected a timeout of {op}, got {other:?}"),
    }
}

/// A connected arbiter that never answers: the call returns at its deadline
/// (before: it waited for good), as a `Timeout`, not an `Io` error.
#[test]
fn a_wedged_arbiter_times_out_at_the_deadline() {
    let arbiter = StallingArbiter::wedged();
    let mut c = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(SHORT));
    let t0 = Instant::now();
    assert_timeout(c.ping(), "ping", SHORT);
    let took = t0.elapsed();
    assert!(took >= SHORT && took < SHORT * 10, "gave up after {took:?}");
    assert_eq!(arbiter.asked_after("ping", 1), 1, "the request reached the arbiter");
}

/// A new client is bounded by default: 5 s for a decision, as the TS
/// client's `DEFAULT_REQUEST_TIMEOUT_MS`.
#[test]
fn a_new_client_is_bounded_at_five_seconds() {
    assert_eq!(DEFAULT_IO_TIMEOUT, Duration::from_secs(5));
    let arbiter = StallingArbiter::wedged();
    let mut c = ArbiterClient::new(&arbiter.socket_path);
    assert_eq!(c.io_timeout(), Some(DEFAULT_IO_TIMEOUT));
    let t0 = Instant::now();
    assert_timeout(c.is_process_tainted("pid-1"), "isProcessTainted", DEFAULT_IO_TIMEOUT);
    let took = t0.elapsed();
    assert!(took >= DEFAULT_IO_TIMEOUT && took < DEFAULT_IO_TIMEOUT * 2, "gave up after {took:?}");
}

/// A report nothing waits on (`emit`) gives up sooner, and never later than
/// the client's own deadline.
#[test]
fn a_report_waits_at_most_the_report_deadline() {
    let arbiter = StallingArbiter::wedged();
    let ev = ManduEvent {
        id: event::new_event_id(),
        session_id: "s".into(),
        turn: 0,
        ts: event::now_iso8601(),
        seq: 0,
        call_id: None,
        parent_id: None,
        kind: event::EventKind::FsAction,
        view: event::View::AgentView,
        boundary: event::Boundary::Filesystem,
        emitter: event::Emitter::FsSupervisor,
        input: None,
        output: None,
        policy: None,
        invariant: event::EventInvariant::ok(),
    };
    let mut long = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(Duration::from_secs(30)));
    let t0 = Instant::now();
    assert_timeout(long.emit(&ev), "emit", REPORT_IO_TIMEOUT);
    assert!(t0.elapsed() < REPORT_IO_TIMEOUT * 3, "a report waited {:?}", t0.elapsed());
    let mut short = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(SHORT));
    assert_timeout(short.emit(&ev), "emit", SHORT);
}

/// After a timeout the connection is dropped: the next request dials a new
/// one (the second connection), and the answer it gets is its own.
#[test]
fn a_timed_out_connection_is_never_reused() {
    let arbiter = StallingArbiter::start(op_stall(|op, _| if op == "isProcessTainted" { Stall::Never } else { pong() }));
    let mut c = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(SHORT));
    assert_timeout(c.is_process_tainted("pid-1"), "isProcessTainted", SHORT);
    assert!(c.ping().expect("a fresh connection answers").pong);
    let mut seen = arbiter.requests_after(2); // each connection's thread reads in its own time
    seen.sort();
    assert_eq!(seen, vec![(1, "isProcessTainted".to_string()), (2, "ping".to_string())]);
    assert_eq!(arbiter.connection_count(), 2);
}

/// The answer to a timed-out request arrives late on its connection; the next
/// request must not read it as its own (on a reused connection it would: the
/// late reply is the first line there). A fresh connection gets ping's answer.
#[test]
fn a_late_answer_is_never_read_as_the_next_requests() {
    let arbiter = StallingArbiter::start(op_stall(|op, _| match op {
        "isProcessTainted" => Stall::AnswerAfter(SHORT + Duration::from_millis(100), Ok(json!({ "tainted": false }))),
        _ => pong(),
    }));
    let mut c = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(SHORT));
    assert_timeout(c.is_process_tainted("pid-1"), "isProcessTainted", SHORT);
    let p = c.ping().expect("ping's own answer");
    assert!(p.pong);
    assert_eq!(arbiter.requests().last(), Some(&(2, "ping".to_string())), "ping went on a new connection");
}

/// An answer that never completes (one byte at a time, never the newline) is
/// bounded by the request's deadline, not by each read's.
#[test]
fn an_answer_trickled_a_byte_at_a_time_still_times_out() {
    let path = std::env::temp_dir().join(format!("mandu-trickle-{}-{:x}.sock", std::process::id(), unique()));
    let listener = UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            for _ in 0..200 {
                if s.write_all(b" ").is_err() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    });
    let mut c = ArbiterClient::new(&path).with_io_timeout(Some(SHORT));
    let t0 = Instant::now();
    assert_timeout(c.ping(), "ping", SHORT);
    assert!(t0.elapsed() < SHORT * 5, "a trickled answer held the call {:?}", t0.elapsed());
    let _ = std::fs::remove_file(&path);
}

/// A listener that never accepts, with its queue full (each timed-out
/// request leaves one more unaccepted connection there): the connect itself
/// gives up at the deadline. Linux: a full queue holds a blocking connect.
#[cfg(target_os = "linux")]
#[test]
fn a_connect_to_a_full_listen_queue_gives_up_at_the_deadline() {
    use std::os::unix::io::AsRawFd;
    let path = std::env::temp_dir().join(format!("mandu-fullq-{}-{:x}.sock", std::process::id(), unique()));
    let listener = UnixListener::bind(&path).unwrap();
    // SAFETY: re-listen our own socket with a queue of one.
    assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
    let _first = std::os::unix::net::UnixStream::connect(&path).expect("the queue's one place");
    let mut c = ArbiterClient::new(&path).with_io_timeout(Some(SHORT));
    let t0 = Instant::now();
    assert_timeout(c.ping(), "ping", SHORT);
    assert!(t0.elapsed() < SHORT * 10, "the connect waited {:?}", t0.elapsed());
    drop(listener);
    let _ = std::fs::remove_file(&path);
}

/// A refusal (`ok: false`) is a whole exchange: the connection stays.
#[test]
fn a_refusal_keeps_the_connection() {
    let arbiter = StallingArbiter::start(op_stall(|op, _| match op {
        "isProcessTainted" => Stall::Answer(Err("no such process".into())),
        _ => pong(),
    }));
    let mut c = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(Some(SHORT));
    assert!(matches!(c.is_process_tainted("pid-1"), Err(ArbiterError::Arbiter(_))));
    assert!(c.ping().unwrap().pong);
    assert_eq!(arbiter.connection_count(), 1);
}

/// `with_io_timeout(None)` waits as long as the arbiter takes (a caller's
/// explicit choice), and a zero deadline is taken as the shortest one.
#[test]
fn the_deadline_can_be_set_or_removed() {
    let arbiter = StallingArbiter::start(op_stall(|_, _| Stall::AnswerAfter(SHORT * 2, Ok(json!({ "pong": true, "protocolVersion": 1 })))));
    let mut c = ArbiterClient::new(&arbiter.socket_path).with_io_timeout(None);
    assert_eq!(c.io_timeout(), None);
    assert!(c.ping().expect("an unbounded call waits for the late answer").pong);
    c.set_io_timeout(Some(SHORT));
    assert_eq!(c.io_timeout(), Some(SHORT));
    assert_timeout(c.ping(), "ping", SHORT);
    c.set_io_timeout(Some(Duration::ZERO));
    assert_eq!(c.io_timeout(), Some(Duration::from_millis(1)));
}

/// A dead endpoint is still an `Io` error (the rediscovery keys on it), not
/// a timeout.
#[test]
fn a_dead_endpoint_is_not_a_timeout() {
    let mut c = ArbiterClient::new("/nonexistent/mandu-timeout.sock").with_io_timeout(Some(SHORT));
    match c.ping() {
        Err(ArbiterError::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
        other => panic!("expected an io error, got {other:?}"),
    }
}

fn unique() -> u64 {
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::Relaxed) ^ (Instant::now().elapsed().as_nanos() as u64)
}
