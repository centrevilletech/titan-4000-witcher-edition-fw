//! The modem console (DM) session behind `titan_pd_model::tk_flags`.
//!
//! One session runs `/usr/lte/lted_cli` interactively on its own thread, so
//! the keeper's packet loop never waits for the modem. Each line goes out
//! about 3 s after the one before, and the session reads what the console
//! printed in between. The decisions (what to send, what a reply means) are
//! in the model crate and tested there. A session that reads a layer's
//! counters (`tk_flags::STATUS`) writes them to `/var/run/witcher-tk.<layer>`.
use std::fs;
use std::io::{Read, Write as _};
use std::process::ChildStdin;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use titan_pd_model::tk_flags::{self, Console, MagicGroup, Outcome, Plan};

/// Console output kept per session. A busy log beyond this is dropped, and
/// a read-back lost that way counts as missing.
const OUTPUT_CAP: usize = 1 << 20;
/// A whole session takes about 30 s. Past this the session stops sending.
const SESSION_LIMIT: Duration = Duration::from_secs(90);
/// A console session's name among the children set aside (`command::stop`).
const STUCK_NAME: &str = "lted_cli";

/// `/var/run/witcher-tk.m1` for M1; `TITAN_TK_M1` overrides it.
fn layer_status_path(group: MagicGroup) -> String {
    std::env::var(format!("TITAN_TK_{}", group.name()))
        .unwrap_or_else(|_| format!("/var/run/{}", tk_flags::status_file(group)))
}

/// Time between two lines. 3 s on the unit, as on the bench.
fn step() -> Duration {
    std::env::var("TITAN_DM_STEP_MS")
        .ok()
        .and_then(|ms| ms.parse::<u64>().ok())
        .filter(|ms| (10..=10_000).contains(ms))
        .map_or(Duration::from_secs(3), Duration::from_millis)
}

struct Cli {
    input: Option<ChildStdin>,
    output: Arc<Mutex<Vec<u8>>>,
    seen: usize,
    step: Duration,
    deadline: Instant,
    timed_out: bool,
}

impl Console for Cli {
    fn command(&mut self, line: &str) -> String {
        if Instant::now() >= self.deadline {
            self.timed_out |= self.input.is_some();
            self.input = None;
        }
        let Some(input) = self.input.as_mut() else {
            return String::new();
        };
        if writeln!(input, "{line}")
            .and_then(|()| input.flush())
            .is_err()
        {
            self.input = None;
            return String::new();
        }
        let wait = if line.starts_with("arm1log") {
            self.step * 2 / 3
        } else {
            self.step
        };
        thread::sleep(wait);
        let output = self.output.lock().unwrap_or_else(|e| e.into_inner());
        let start = self.seen.min(output.len());
        let text = String::from_utf8_lossy(&output[start..]).into_owned();
        self.seen = output.len();
        text
    }
}

/// Run one session to the end. Never panics; a console that cannot start is
/// no reply. The session holds the modem console from start to end
/// (`console_lock`), and never waits for it: while a radio worker holds it,
/// the session is `Busy`, which spends no attempt.
pub fn run(plan: &Plan) -> (Outcome, bool) {
    let Some(_console) = crate::console_lock::try_hold() else {
        return (Outcome::Busy, false);
    };
    // An earlier console that never exited (stuck in the kernel): no reply,
    // so the writer looks again later without piling up consoles.
    if crate::command::still_stuck(STUCK_NAME) {
        return (Outcome::NoReply, false);
    }
    let spawned = crate::radio_modem::spawn_console(&crate::radio_modem::cli_path());
    let Ok(mut child) = spawned else {
        return (Outcome::NoReply, false);
    };
    let output = Arc::new(Mutex::new(Vec::new()));
    let reader = child.stdout.take().map(|mut out| {
        let sink = Arc::clone(&output);
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match out.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut all = sink.lock().unwrap_or_else(|e| e.into_inner());
                        if all.len() + n <= OUTPUT_CAP {
                            all.extend_from_slice(&buf[..n]);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
        })
    });
    let mut cli = Cli {
        input: child.stdin.take(),
        output,
        seen: 0,
        step: step(),
        deadline: Instant::now() + SESSION_LIMIT,
        timed_out: false,
    };
    let report = tk_flags::run_plan_report(&mut cli, plan);
    if let Some(mut input) = cli.input.take() {
        let _ = writeln!(input, "exit");
    }
    // The vendor CLI may stay alive after EOF. Give it a moment to release
    // its client slot before stopping it.
    for _ in 0..20 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    // A console stuck in the kernel is set aside rather than waited for, so
    // the session always ends and the next one can be planned.
    let exited = matches!(child.try_wait(), Ok(Some(_))) || crate::command::stop(child, STUCK_NAME);
    if let Some(reader) = reader.filter(|_| exited) {
        let _ = reader.join();
    }
    if cli.timed_out {
        // The session stopped before its own `arm1log 1`.
        let _ = crate::radio_modem::console("arm1log 1");
    }
    let now = crate::clock::monotonic();
    for status in &report.status {
        let _ = fs::write(layer_status_path(status.group), status.text(now));
    }
    (report.outcome, report.sent)
}

/// Start a session on its own thread.
pub fn spawn(plan: Plan) -> Option<thread::JoinHandle<(Outcome, bool)>> {
    thread::Builder::new()
        .name("tk-flags".into())
        .spawn(move || run(&plan))
        .ok()
}
