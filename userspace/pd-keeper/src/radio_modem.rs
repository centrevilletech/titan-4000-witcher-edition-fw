//! The CLI needs a live stdin while responses arrive. Drain asynchronous modem
//! text concurrently and bound the capture even when diagnostic logging is busy.
//! Every session holds the console (`console_lock`); a radio worker holds it
//! for its whole run, so its own sessions nest.
use std::{
    io::{self, Read, Write},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

/// Start the vendor's modem console `program` with stdin and stdout piped
/// and its stderr on stdout.
pub fn spawn_console(program: &str) -> io::Result<Child> {
    Command::new("/bin/sh")
        .args(["-c", "exec \"$0\" 2>&1", program])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// The vendor's modem console (`TITAN_LTED_CLI` in tests).
pub fn cli_path() -> String {
    crate::paths::env_or("TITAN_LTED_CLI", "/usr/lte/lted_cli")
}

pub fn console(cmd: &str) -> io::Result<String> {
    let _console = crate::console_lock::hold(crate::console_lock::RADIO_WAIT)?;
    let dm = !cmd.starts_with("AT") && cmd != "arm1log 1";
    // A hint for bench tools, and how a later restore knows a DM query was
    // cut short with the console still logging.
    let marker = std::path::Path::new(crate::radio::RAM).join("radio-console-open");
    if dm {
        std::fs::write(&marker, b"1")?;
    }
    let mut child = spawn_console(&cli_path())?;
    let mut out = child.stdout.take().unwrap();
    let capture = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut buf = [0; 4096];
        let mut result = Vec::new();
        loop {
            let n = out.read(&mut buf)?;
            if n == 0 {
                break;
            }
            if result.len() + n <= 65536 {
                result.extend_from_slice(&buf[..n]);
            } else {
                return Err(io::Error::other("console reply too large"));
            }
        }
        Ok(result)
    });
    let mut input = child.stdin.take().unwrap();
    let send = |pipe: &mut std::process::ChildStdin, line: &str| -> io::Result<()> {
        writeln!(pipe, "{line}")?;
        thread::sleep(Duration::from_secs(1));
        Ok(())
    };
    let result = (|| {
        if dm {
            send(&mut input, "arm1log 2")?;
        }
        send(&mut input, cmd)?;
        thread::sleep(Duration::from_secs(1));
        Ok::<_, io::Error>(())
    })();
    let restore = if dm {
        send(&mut input, "arm1log 1")
    } else {
        Ok(())
    };
    let _ = writeln!(input, "exit");
    drop(input);
    // The vendor CLI may stay alive after EOF. Give it a chance to release
    // the HCI client slot before stopping it.
    for _ in 0..10 {
        if child.try_wait()?.is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let closed = child.try_wait()?.is_some_and(|s| s.success());
    if !closed {
        let _ = child.kill();
    }
    child.wait()?;
    let bytes = capture
        .join()
        .map_err(|_| io::Error::other("console reader stopped"))??;
    result?;
    restore?;
    if !closed {
        return Err(io::Error::other("console did not close cleanly"));
    }
    if dm || cmd == "arm1log 1" {
        let _ = std::fs::remove_file(&marker);
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Seconds the radio may take to go off before the switch fails.
const OFF_SECS: u64 = 20;

/// The vendor's attach state from its RAM configuration cache.
pub fn media() -> String {
    crate::nvram::read_value("sqns_connection_mediaState")
}

/// Switch the radio. `AT+CFUN?` is no read-back on this stack: on the bench it
/// kept answering `+CFUN: 1` for the whole time the radio was off
/// (2026-11-24). The modem's `OK` accepts the switch. Off is confirmed when the
/// attach state leaves `ATTACHED` (about 5 s on the bench, then `DISCONNECTED`
/// and `Not Searching`). On is confirmed by the attach the caller waits for
/// (about 17 s on the bench).
pub fn cfun(on: bool) -> io::Result<()> {
    let n = if on { 1 } else { 0 };
    let reply = console(&format!("AT+CFUN={n}"))?;
    if !reply.lines().any(|s| s.trim() == "OK") {
        return Err(io::Error::other("CFUN not accepted"));
    }
    if on {
        return Ok(());
    }
    let start = std::time::Instant::now();
    loop {
        if media() != "ATTACHED" {
            return Ok(());
        }
        if start.elapsed() >= Duration::from_secs(OFF_SECS) {
            return Err(io::Error::other("radio did not go off"));
        }
        thread::sleep(Duration::from_secs(1));
    }
}
