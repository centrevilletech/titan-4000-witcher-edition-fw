//! Signals, scheduling priority, reaping, the effective user, and what a
//! child runs between `fork` and `exec`.

use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::Command;

use libc::c_int;

use crate::cvt;

/// The signals the keeper sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// `SIGKILL`.
    Kill,
    /// `SIGSTOP`: pause a process.
    Stop,
    /// `SIGCONT`: let a paused process run again.
    Continue,
    /// `SIGUSR1`, which tells `rcinit` to apply settings.
    User1,
}

impl Signal {
    fn number(self) -> c_int {
        match self {
            Self::Kill => libc::SIGKILL,
            Self::Stop => libc::SIGSTOP,
            Self::Continue => libc::SIGCONT,
            Self::User1 => libc::SIGUSR1,
        }
    }
}

fn refuse() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidInput)
}

/// Send `signal` to the one process `pid`. `kill(2)` gives 0 and negative
/// pids a group or broadcast meaning, so they are refused.
pub fn kill(pid: i32, signal: Signal) -> io::Result<()> {
    if pid <= 0 {
        return Err(refuse());
    }
    // SAFETY: `kill` takes only integers.
    let rc = unsafe { libc::kill(pid, signal.number()) };
    cvt(rc).map(drop)
}

/// Send `signal` to every process in group `group` (`kill(-group, signal)`).
pub fn kill_group(group: i32, signal: Signal) -> io::Result<()> {
    if group <= 0 {
        return Err(refuse());
    }
    // SAFETY: `kill` takes only integers.
    let rc = unsafe { libc::kill(-group, signal.number()) };
    cvt(rc).map(drop)
}

/// Set the nice value of the one process `pid`
/// (`setpriority(PRIO_PROCESS, pid, nice)`).
pub fn set_nice(pid: i32, nice: i32) -> io::Result<()> {
    if pid <= 0 {
        return Err(refuse());
    }
    // SAFETY: `setpriority` takes only integers.
    let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS as _, pid as libc::id_t, nice) };
    cvt(rc).map(drop)
}

/// Reap child `pid` if it has exited (`waitpid(pid, NULL, WNOHANG)`): true
/// once reaped, false while it still runs. An error means `pid` is not a
/// child of this process (any more).
pub fn try_reap(pid: i32) -> io::Result<bool> {
    if pid <= 0 {
        return Err(refuse());
    }
    // SAFETY: a null status pointer asks for no status; the rest are integers.
    let rc = unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) };
    cvt(rc).map(|reaped| reaped != 0)
}

/// This process's effective user id.
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments and always succeeds.
    unsafe { libc::geteuid() }
}

/// What a child runs between `fork` and `exec`. Both hooks only make
/// async-signal-safe calls and allocate nothing, as a forked child of a
/// threaded parent must.
pub trait SpawnExt {
    /// Start the child in a session of its own (`setsid`), so it does not
    /// stop with this process's session.
    fn new_session(&mut self) -> &mut Self;

    /// Have the kernel kill the child with `SIGKILL` when the thread that
    /// spawned it exits, and refuse to start it if its parent is no longer
    /// `parent` (the parent died during the spawn). The refusal reaches the
    /// spawner as `EINVAL`.
    fn die_with_parent(&mut self, parent: u32) -> &mut Self;
}

impl SpawnExt for Command {
    fn new_session(&mut self) -> &mut Self {
        // SAFETY: `start_session` only calls `setsid` and reads `errno`, which
        // is safe between `fork` and `exec`.
        unsafe { self.pre_exec(start_session) }
    }

    fn die_with_parent(&mut self, parent: u32) -> &mut Self {
        let parent = parent as libc::pid_t;
        // SAFETY: `die_with` only calls `prctl` and `getppid`, which is safe
        // between `fork` and `exec`.
        unsafe { self.pre_exec(move || die_with(parent)) }
    }
}

fn start_session() -> io::Result<()> {
    // SAFETY: `setsid` takes no arguments.
    let rc = unsafe { libc::setsid() };
    cvt(rc).map(drop)
}

fn die_with(parent: libc::pid_t) -> io::Result<()> {
    // SAFETY: `PR_SET_PDEATHSIG` takes a signal number and reads no memory.
    let armed = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) };
    if armed != 0 {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    // SAFETY: `getppid` takes no arguments and always succeeds.
    let current = unsafe { libc::getppid() };
    if current != parent {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn sleeper() -> Command {
        let mut command = Command::new("sleep");
        command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
    }

    #[test]
    fn a_killed_child_dies_of_that_signal() {
        let mut child = sleeper().spawn().unwrap();
        kill(child.id() as i32, Signal::Kill).unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn a_group_signal_reaches_the_group() {
        let mut child = sleeper().process_group(0).spawn().unwrap();
        kill_group(child.id() as i32, Signal::Kill).unwrap();
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGKILL));
    }

    #[test]
    fn only_one_process_or_one_group_is_ever_named() {
        for pid in [0, -1] {
            assert_eq!(kill(pid, Signal::Continue).unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(kill_group(pid, Signal::Continue).unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(set_nice(pid, 0).unwrap_err().kind(), io::ErrorKind::InvalidInput);
            assert_eq!(try_reap(pid).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn a_missing_process_cannot_be_reniced() {
        let err = set_nice(i32::MAX, 0).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::ESRCH));
    }

    #[test]
    fn an_exited_child_is_reaped_once() {
        let child = Command::new("true").spawn().unwrap();
        let pid = child.id() as i32;
        let deadline = Instant::now() + Duration::from_secs(10);
        while !try_reap(pid).unwrap() {
            assert!(Instant::now() < deadline, "true did not exit");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(try_reap(pid).unwrap_err().raw_os_error(), Some(libc::ECHILD));
        drop(child);
    }

    #[test]
    fn a_new_session_is_led_by_the_child() {
        let mut child = sleeper().new_session().spawn().unwrap();
        let stat = std::fs::read_to_string(format!("/proc/{}/stat", child.id())).unwrap();
        // After the command name: state, parent, process group, session.
        let fields: Vec<&str> = stat.rsplit_once(')').unwrap().1.split_whitespace().collect();
        assert_eq!(fields[3], child.id().to_string());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_child_starts_only_under_the_named_parent() {
        let mut child = sleeper().die_with_parent(std::process::id()).spawn().unwrap();
        let _ = child.kill();
        let _ = child.wait();
        let err = sleeper().die_with_parent(1).spawn().unwrap_err();
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    }

    #[test]
    fn the_effective_user_owns_what_it_creates() {
        let path = std::env::temp_dir().join(format!("titan-sys-euid-{}", std::process::id()));
        std::fs::write(&path, b"").unwrap();
        let owner = std::fs::metadata(&path).unwrap().uid();
        let _ = std::fs::remove_file(&path);
        assert_eq!(owner, effective_uid());
    }
}
