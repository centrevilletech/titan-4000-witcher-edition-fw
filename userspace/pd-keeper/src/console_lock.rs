//! One owner at a time for the vendor's modem console (`lted_cli`).
//!
//! The radio profile's workers and the modem flag writer both drive the
//! console, and two sessions at once cut each other's replies short. On the
//! bench a flag session cut a radio reply short and reverted a profile
//! (2026-11-24), and the radio checks made the flag writer give up
//! (2026-11-25). Every session therefore holds `console.lock` in the keeper's
//! RAM directory with `flock` for its whole length. The kernel drops the lock
//! when its holder exits or dies, so it never goes stale.
//!
//! - The flag writer never waits (`try_hold`): a held console is its
//!   `Outcome::Busy`, which spends no attempt.
//! - A radio worker waits (`hold`) up to `RADIO_WAIT`, longer than a whole flag
//!   session; a radio check waits `CHECK_WAIT`. Past that it reports `BUSY`,
//!   which the guard treats as no verdict, never as a failure.
//! - A thread that holds the console may open more sessions inside it (a radio
//!   cycle's several commands, a flag session's closing `arm1log 1`) without
//!   waiting on itself.
//! - With no lock file to open, a session runs unlocked as before v1.0.17,
//!   rather than never.
//!
//! A bench tool can take the same lock around its own session with `flock(1)`
//! on `/tmp/titan-pd-keeper/console.lock`.

use std::cell::Cell;
use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

/// What a session that could not get the console reports.
pub const BUSY: &str = "modem console busy";
/// A radio worker's wait: past a whole flag session (90 s) and its close.
pub const RADIO_WAIT: Duration = Duration::from_secs(100);
/// A radio check's wait. A skipped check costs nothing; the next is 30 s on.
pub const CHECK_WAIT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(200);

thread_local! {
    /// This thread holds the console.
    static HELD: Cell<bool> = const { Cell::new(false) };
}

fn lock_path() -> PathBuf {
    crate::paths::runtime_dir().join("console.lock")
}

/// The console, held until dropped.
#[must_use = "the console is let go when the hold is dropped"]
pub struct Hold {
    /// This hold took the console, rather than nesting in one this thread
    /// already holds.
    owner: bool,
    _file: Option<File>,
}

impl Drop for Hold {
    fn drop(&mut self) {
        if self.owner {
            HELD.with(|held| held.set(false));
        }
        // `_file` closes after this, which lets go of the `flock`.
    }
}

fn taken(file: Option<File>) -> Hold {
    HELD.with(|held| held.set(true));
    Hold { owner: true, _file: file }
}

fn try_hold_at(path: &Path) -> Option<Hold> {
    if HELD.with(Cell::get) {
        return Some(Hold {
            owner: false,
            _file: None,
        });
    }
    let opened = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path);
    let Ok(file) = opened else {
        return Some(taken(None));
    };
    match file.try_lock() {
        Ok(()) => Some(taken(Some(file))),
        Err(TryLockError::WouldBlock) => None,
        Err(TryLockError::Error(_)) => Some(taken(None)),
    }
}

fn hold_at(path: &Path, wait: Duration) -> io::Result<Hold> {
    let start = Instant::now();
    loop {
        if let Some(hold) = try_hold_at(path) {
            return Ok(hold);
        }
        if start.elapsed() >= wait {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, BUSY));
        }
        thread::sleep(POLL);
    }
}

/// The console now, or `None` while another session holds it.
pub fn try_hold() -> Option<Hold> {
    try_hold_at(&lock_path())
}

/// The console within `wait`, or the error `BUSY`.
pub fn hold(wait: Duration) -> io::Result<Hold> {
    hold_at(&lock_path(), wait)
}

/// Whether `err` is `BUSY`, as `hold` returns it or a worker reported it.
pub fn busy(err: &io::Error) -> bool {
    err.to_string() == BUSY
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("witcher-console-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Hold the console on another thread until told to let go.
    fn holder(path: PathBuf) -> (mpsc::Sender<()>, thread::JoinHandle<()>) {
        let (held_tx, held_rx) = mpsc::channel();
        let (go_tx, go_rx) = mpsc::channel::<()>();
        let thread = thread::spawn(move || {
            let hold = try_hold_at(&path).expect("free");
            held_tx.send(()).unwrap();
            let _ = go_rx.recv();
            drop(hold);
        });
        held_rx.recv().unwrap();
        (go_tx, thread)
    }

    #[test]
    fn one_session_at_a_time_and_the_lock_goes_with_its_holder() {
        let path = dir("one").join("console.lock");
        let (go, thread) = holder(path.clone());
        // A flag session never waits: busy now.
        assert!(try_hold_at(&path).is_none());
        // A radio worker waits, then reports busy, as no verdict.
        let start = Instant::now();
        let err = hold_at(&path, Duration::from_millis(300)).err().expect("busy");
        assert!(busy(&err) && start.elapsed() >= Duration::from_millis(300));
        // The holder lets go (or dies): the console is free at once.
        go.send(()).unwrap();
        thread.join().unwrap();
        assert!(try_hold_at(&path).is_some());
    }

    #[test]
    fn a_waiting_worker_gets_the_console_when_the_session_ends() {
        let path = dir("wait").join("console.lock");
        let (go, thread) = holder(path.clone());
        let ender = thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            go.send(()).unwrap();
        });
        assert!(hold_at(&path, Duration::from_secs(10)).is_ok());
        ender.join().unwrap();
        thread.join().unwrap();
    }

    #[test]
    fn a_holder_nests_without_waiting_on_itself() {
        let path = dir("nest").join("console.lock");
        let outer = try_hold_at(&path).expect("free");
        let inner = hold_at(&path, Duration::ZERO).expect("nested");
        drop(inner);
        // Dropping the inner hold kept the console: another thread waits.
        let other = path.clone();
        assert!(thread::spawn(move || try_hold_at(&other).is_none()).join().unwrap());
        drop(outer);
        let other = path.clone();
        assert!(thread::spawn(move || try_hold_at(&other).is_some()).join().unwrap());
    }

    #[test]
    fn without_a_lock_file_a_session_still_runs() {
        let path = dir("none").join("missing").join("console.lock");
        let hold = try_hold_at(&path);
        assert!(hold.is_some());
    }
}
