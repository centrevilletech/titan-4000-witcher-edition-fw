//! Running the vendor's programs.

use std::process::Command;

/// What `program` printed, or nothing when it could not run. Its exit
/// status is not looked at.
pub fn command_stdout(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

/// Run `program` to its end: `Ok` when it exits 0, else the command line and
/// what it printed on stderr.
pub fn run_status(program: &str, args: &[&str]) -> Result<(), String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|err| err.to_string())?;
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

/// What `program` printed, when it exited 0.
pub fn stdout_if_success(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}
