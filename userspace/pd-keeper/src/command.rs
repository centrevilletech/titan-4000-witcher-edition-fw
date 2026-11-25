//! Running the vendor's programs.
//!
//! Every child the keeper waits for runs within `LIMIT` (v1.0.17). One that
//! hangs (a `kern` ioctl into a wedged LTE driver, `ip` or `tc` waiting on
//! RTNL, a vendor tool waiting on its lock) is stopped, so the keeper's loop,
//! and with it the CBRS gate, the DHCP and ARP repairs and the deaf watchdog,
//! never stops on one. A child that does not exit when stopped (stuck in the
//! kernel) is set aside and reaped later, and its program is not started
//! again until then, so a wedged driver cannot pile up processes.

use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::process::{Child, Command, Output, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// How long one child may run before the keeper stops it.
pub const LIMIT: Duration = Duration::from_secs(10);
/// How long a stopped child gets to exit before it is set aside.
const STOP_GRACE: Duration = Duration::from_millis(200);
/// Output kept from each of a child's streams; the rest is read and dropped.
const OUTPUT_CAP: usize = 1 << 20;

/// Children stopped past their time that had not exited, with their program.
static STUCK: Mutex<Vec<(String, Child)>> = Mutex::new(Vec::new());

/// `command.output()` within `LIMIT`: stdin empty, stdout and stderr read.
/// A child still running at the limit is stopped (`stop`) and gives a
/// `TimedOut` error, as does a program whose last child is still stuck.
pub fn output(command: &mut Command) -> io::Result<Output> {
    output_within(command, None, LIMIT)
}

/// `output` with `input` on the child's stdin.
pub fn output_with_input(command: &mut Command, input: &[u8]) -> io::Result<Output> {
    output_within(command, Some(input), LIMIT)
}

fn output_within(command: &mut Command, input: Option<&[u8]>, limit: Duration) -> io::Result<Output> {
    let program = command.get_program().to_string_lossy().into_owned();
    if still_stuck(&program) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("{program} is not started while an earlier one is stuck"),
        ));
    }
    let mut child = command
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        // A setting's value: the pipe takes it at once. Dropping it ends it.
        let _ = stdin.write_all(bytes);
    }
    let deadline = Instant::now() + limit;
    let (stdout, stderr) = read_both(&mut child, deadline);
    let mut nap = Duration::from_millis(1);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Output { status, stdout, stderr });
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            crate::log_ram(&format!(
                "{program} did not finish within {} s; stopping it",
                limit.as_secs()
            ));
            stop(child, &program);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{program} did not finish within {} s", limit.as_secs()),
            ));
        }
        thread::sleep(nap.min(left));
        nap = (nap * 2).min(Duration::from_millis(50));
    }
}

/// The child's stdout and stderr, read until both end or `deadline`.
fn read_both(child: &mut Child, deadline: Instant) -> (Vec<u8>, Vec<u8>) {
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    while out.is_some() || err.is_some() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let fds = [out.as_ref().map(AsFd::as_fd), err.as_ref().map(AsFd::as_fd)];
        match titan_sys::poll::wait_readable(&fds, left) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
        read_ready(&mut out, &mut stdout);
        read_ready(&mut err, &mut stderr);
    }
    (stdout, stderr)
}

/// One read from `pipe` when it is ready now (so the read cannot block);
/// the pipe is dropped at its end.
fn read_ready<R: Read + AsFd>(pipe: &mut Option<R>, into: &mut Vec<u8>) {
    let Some(reader) = pipe.as_mut() else {
        return;
    };
    if !matches!(titan_sys::poll::wait_readable(&[Some(reader.as_fd())], Duration::ZERO), Ok(1)) {
        return;
    }
    let mut buf = [0u8; 4096];
    match reader.read(&mut buf) {
        Ok(0) => *pipe = None,
        Ok(n) => {
            let room = OUTPUT_CAP.saturating_sub(into.len());
            into.extend_from_slice(&buf[..n.min(room)]);
        }
        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
        Err(_) => *pipe = None,
    }
}

/// Stop `child`, which ran past its time. True when it exited; one that does
/// not exit within a moment (stuck in the kernel) is set aside to be reaped
/// later, and `program` is not started again until it is gone.
pub fn stop(mut child: Child, program: &str) -> bool {
    let _ = child.kill();
    let deadline = Instant::now() + STOP_GRACE;
    loop {
        if !matches!(child.try_wait(), Ok(None)) {
            return true;
        }
        if Instant::now() >= deadline {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    crate::log(&format!(
        "{program} did not exit when stopped (stuck in the kernel?); it is not started again until it exits"
    ));
    STUCK
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push((program.to_owned(), child));
    false
}

/// Reap the set-aside children that have exited since; whether one of
/// `program`'s is still there.
pub fn still_stuck(program: &str) -> bool {
    let mut stuck = STUCK.lock().unwrap_or_else(|e| e.into_inner());
    stuck.retain_mut(|(_, child)| matches!(child.try_wait(), Ok(None)));
    stuck.iter().any(|(name, _)| name == program)
}

/// What `program` printed, or nothing when it could not run or ran out of
/// time. Its exit status is not looked at.
pub fn command_stdout(program: &str, args: &[&str]) -> String {
    output(Command::new(program).args(args))
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

/// Run `program` to its end: `Ok` when it exits 0, else the command line and
/// what it printed on stderr (or why it did not run or finish).
pub fn run_status(program: &str, args: &[&str]) -> Result<(), String> {
    let output = output(Command::new(program).args(args)).map_err(|err| err.to_string())?;
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr);
        Err(format!("{program} {}: {}", args.join(" "), err.trim()))
    }
}

/// `ebtables` (`TITAN_EBTABLES` in tests).
pub fn ebtables_program() -> String {
    crate::paths::env_or("TITAN_EBTABLES", "/usr/bin/ebtables")
}

/// What `program` printed, when it exited 0 in time.
pub fn stdout_if_success(program: &str, args: &[&str]) -> Option<String> {
    let out = output(Command::new(program).args(args)).ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn a_child_reads_like_output_and_gets_its_input() {
        let out = output(&mut sh("echo out; echo err >&2; exit 3")).unwrap();
        assert_eq!(out.status.code(), Some(3));
        assert_eq!(out.stdout, b"out\n");
        assert_eq!(out.stderr, b"err\n");
        let out = output_with_input(&mut sh("read v; echo got=$v"), b"5").unwrap();
        assert_eq!(out.stdout, b"got=5\n");
        // A child that fills both pipes is drained while it runs.
        let out = output(&mut sh("i=0; while [ $i -lt 2000 ]; do echo 0123456789abcdef0123456789abcdef; echo e >&2; i=$((i+1)); done")).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout.len(), 2000 * 33);
        assert_eq!(out.stderr.len(), 2000 * 2);
        assert_eq!(command_stdout("/bin/sh", &["-c", "printf x"]), "x");
        assert!(run_status("/bin/sh", &["-c", "echo no >&2; exit 1"]).unwrap_err().ends_with(": no"));
    }

    /// The landmine: one hung child froze the whole loop until a reboot.
    #[test]
    fn a_hung_child_is_stopped_at_its_limit() {
        let start = Instant::now();
        let err = output_within(&mut sh("echo started; exec sleep 30"), None, Duration::from_millis(300)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let took = start.elapsed();
        assert!(took >= Duration::from_millis(300) && took < Duration::from_secs(5), "{took:?}");
        // A child that closes its output but keeps running is stopped too.
        let err = output_within(&mut sh("exec >&- 2>&-; exec sleep 30"), None, Duration::from_millis(300)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        // It was killed and reaped, so the next run of the program goes ahead.
        assert!(!still_stuck("/bin/sh"));
        assert!(output(&mut sh("exit 0")).unwrap().status.success());
    }

    #[test]
    fn a_child_that_does_not_die_blocks_only_its_own_program() {
        // Stand-in for a child stuck in the kernel: one that `try_wait`
        // never sees exit is set aside, and its program waits for it.
        let child = sh("exec sleep 30").spawn().unwrap();
        STUCK.lock().unwrap().push(("stuck-tool".into(), child));
        assert!(still_stuck("stuck-tool"));
        let err = output(&mut Command::new("stuck-tool")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(output(&mut sh("exit 0")).is_ok(), "another program still runs");
        // Once it exits it is reaped, and the program may run again.
        for (name, child) in STUCK.lock().unwrap().iter_mut() {
            if name == "stuck-tool" {
                let _ = child.kill();
            }
        }
        let until = Instant::now() + Duration::from_secs(5);
        while still_stuck("stuck-tool") && Instant::now() < until {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!still_stuck("stuck-tool"));
    }
}
