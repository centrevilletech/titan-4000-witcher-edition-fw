//! `filter-probe`: install the customer port's egress filter and take it off
//! again, with a second process as a safety timer so a probe cannot
//! black-hole the port.

use std::env;
use std::fs;
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

use titan_sys::process::SpawnExt;

use crate::{log, run};

/// Install the egress filter and take it off again. A second process removes it
/// if this one does not finish, so a probe cannot black-hole the port.
pub fn probe() -> i32 {
    let dev = "eth0";
    let _ = spawn_undo(dev);
    if let Err(err) = run::tc_apply(&titan_pd_model::filter::install(dev)) {
        log(&format!("filter probe could not install: {err}"));
        let _ = run::tc_apply(&titan_pd_model::filter::remove(dev));
        return 1;
    }
    log("filter probe installed for 20s");
    thread::sleep(Duration::from_secs(20));
    match run::tc_apply(&titan_pd_model::filter::remove(dev)) {
        Ok(()) => {
            let _ = fs::write("/tmp/titan-pd-filter-probe.done", "done");
            0
        }
        Err(err) => {
            // Leave the done file absent so the safety timer tries again.
            log(&format!("filter probe could not remove: {err}"));
            1
        }
    }
}

pub fn undo(args: &[String]) -> i32 {
    let dev = args.first().map(String::as_str).unwrap_or("eth0");
    thread::sleep(Duration::from_secs(30));
    if fs::read_to_string("/tmp/titan-pd-filter-probe.done").is_err() {
        let _ = run::tc_apply(&titan_pd_model::filter::remove(dev));
        log("filter probe safety timer removed the egress filter");
    }
    0
}

fn spawn_undo(dev: &str) -> Result<(), ()> {
    let exe = env::current_exe().map_err(|_| ())?;
    Command::new(exe)
        .arg("filter-undo")
        .arg(dev)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .new_session()
        .spawn()
        .map(|_| ())
        .map_err(|_| ())?;
    let dev = dev.to_owned();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(30));
        if fs::read_to_string("/tmp/titan-pd-filter-probe.done").is_err() {
            let _ = run::tc_apply(&titan_pd_model::filter::remove(&dev));
            log("filter probe safety timer removed the egress filter");
        }
    });
    Ok(())
}
