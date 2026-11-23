//! Prefix keeper for a Titan in IP passthrough.
//!
//! `run` is the supervised process. `guard` and `confirm` are the self-revert
//! pair for a setting change that re-attaches LTE: the guard puts the old
//! setting back if confirm has not recorded that management returned.
//! `solicit-mgmt` is a diagnostic: it sends one router solicitation on the
//! management bearer, to check that the answer no longer reaches the vendor
//! stack once the keeper has closed the bearer to advertisements.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use titan_pd_model::config::{self, Pending, Recovery};
use titan_pd_model::wear;

mod bench;
mod capture;
mod carrier_watch_io;
mod radio;
mod radio_modem;
mod qctrl_io;
mod radio_sqm;
mod run;
mod tk_flags_io;

fn main() {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("run") | None => {
            if env::var_os("TITAN_PD_STATE").is_none() && !config::persistent_volume_mounted() {
                log("persistent volume is not mounted; keeper state is under /tmp");
            }
            recover_pending();
            radio::supervise();
            if let Err(err) = run::serve() {
                log(&format!("keeper stopped: {err}"));
                std::process::exit(1);
            }
        }
        Some(op @ ("radio-profile" | "opt-guard" | "radio-worker")) => {
            let result = match op {
                "radio-profile" => radio::api(args.next().as_deref()),
                "opt-guard" => radio::guard(),
                _ => radio::worker(args.next().as_deref()),
            };
            if let Err(e) = result {
                eprintln!("{op}: {e}");
                std::process::exit(1);
            }
        }
        Some("guard") => std::process::exit(guard(&args.collect::<Vec<_>>())),
        Some("confirm") => std::process::exit(confirm(&args.collect::<Vec<_>>())),
        Some("filter-probe") => std::process::exit(filter_probe()),
        Some("filter-undo") => std::process::exit(filter_undo(&args.collect::<Vec<_>>())),
        Some("solicit-mgmt") => match run::solicit_once() {
            Ok(source) => {
                let _ = writeln!(
                    std::io::stdout(),
                    "router solicitation sent on lte0pdn0 from {source}"
                );
            }
            Err(err) => {
                eprintln!("solicit-mgmt: {err}");
                std::process::exit(1);
            }
        },
        Some("bench-bridge-endpoints") => {
            let result = args
                .next()
                .and_then(|s| s.parse().ok())
                .and_then(bench::endpoints);
            match result {
                Some(line) => println!("{line}"),
                None => std::process::exit(1),
            }
        }
        Some("status") => {
            // The RAM copy is current. The flash copy can lag by up to a minute.
            let live = fs::read_to_string(runtime().join("status.json"))
                .or_else(|_| fs::read_to_string(state().join("status.json")))
                .unwrap_or_default();
            let _ = writeln!(std::io::stdout(), "{live}");
        }
        _ => {
            eprintln!(
                "usage: titan-pd-keeper run|guard|confirm|filter-probe|filter-undo|solicit-mgmt|status"
            );
            std::process::exit(64);
        }
    }
}

pub(crate) fn state() -> PathBuf {
    config::default_state_dir()
}

/// The keeper's RAM directory (`/tmp` is RAM on the Titan). Hot files live here.
pub(crate) fn runtime() -> PathBuf {
    env::var_os("TITAN_PD_RUNTIME")
        .map_or_else(|| PathBuf::from("/tmp/titan-pd-keeper"), PathBuf::from)
}

/// The guard process did not survive (a reboot kills it). Put the previous
/// setting back once, after commit and before the re-attach, so a crash in the
/// re-attach cannot loop. The decision uses the boot, not the wall clock: the
/// unit boots in 2013 until NTP answers (see `config::recovery`).
fn recover_pending() {
    let first = note_boot();
    let path = state().join("pending.json");
    let Ok(Some(pending)) = config::load_pending(&path) else {
        return;
    };
    let confirm_file =
        fs::read_to_string(state().join(format!("confirm-{}", pending.token))).unwrap_or_default();
    let decision = config::recovery(
        guard_running(),
        config::confirmed(&pending.token, &confirm_file),
        first,
        wall_now(),
        pending.not_before,
    );
    match decision {
        Recovery::Wait => {}
        Recovery::Keep => {
            let _ = fs::remove_file(&path);
            log("pending setting change: management had returned before its guard was lost; keeping the new setting");
        }
        Recovery::Revert => {
            log("pending setting change had no guard left; restoring the previous IP family");
            wait_for_nvram_cache();
            if !finish_revert(&pending) {
                log("could not restore ip_proto from the pending setting change");
            }
        }
    }
}

/// True on the keeper's first start in this boot. The marker sits in RAM, so a
/// reboot clears it, and it holds the kernel's boot id in case it does not.
fn note_boot() -> bool {
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap_or_default();
    let marker = runtime().join("boot-id");
    let seen = fs::read_to_string(&marker).ok();
    let first = config::first_start(seen.as_deref(), &boot_id);
    if first {
        let _ = fs::create_dir_all(runtime());
        let text = if boot_id.trim().is_empty() { "seen" } else { boot_id.trim() };
        let _ = fs::write(&marker, text);
    }
    first
}

/// The vendor's RAM configuration cache appears early in boot. A revert at
/// keeper start must not run before it, or the nvram writes fail.
fn wait_for_nvram_cache() {
    if env::var_os("TITAN_NVRAM").is_some() {
        return;
    }
    let ready = || fs::metadata("/tmp/nvram.cfg").is_ok_and(|meta| meta.len() > 0);
    let start = Instant::now();
    while !ready() && start.elapsed() < Duration::from_secs(60) {
        thread::sleep(Duration::from_secs(1));
    }
}

fn wall_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn guard_running() -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if pid == std::process::id() as i32 {
            continue;
        }
        let cmdline = fs::read(entry.path().join("cmdline")).unwrap_or_default();
        let text = String::from_utf8_lossy(&cmdline);
        if text.contains("titan-pd-keeper") && text.split('\0').any(|arg| arg == "guard") {
            return true;
        }
    }
    false
}

fn finish_revert(pending: &Pending) -> bool {
    if pending.absent {
        let _ = fs::remove_file(state().join("config.json"));
    } else if let Err(err) =
        fs::rename(state().join("config.previous"), state().join("config.json"))
    {
        log(&format!("could not restore the setting file: {err}"));
    }
    if nvram_set("ip_proto", &pending.ip_proto).is_err()
        || nvram_set("sqns_admin_apply", "1").is_err()
        || nvram_commit().is_err()
    {
        return false;
    }
    let _ = fs::remove_file(state().join("pending.json"));
    let _ = signal_rcinit();
    true
}

/// A real event: the flash log (`keeper.log` in the state directory) and the
/// RAM log, which holds every line.
pub fn log(line: &str) {
    let text = stamped(line);
    let state = state();
    append(&state, &text, wear::FLASH_LOG_BYTES);
    if runtime() != state {
        append(&runtime(), &text, wear::RAM_LOG_BYTES);
    }
    eprintln!("{line}");
}

/// A routine line: the RAM log only, so it never wears the flash.
pub fn log_ram(line: &str) {
    append(&runtime(), &stamped(line), wear::RAM_LOG_BYTES);
}

fn stamped(line: &str) -> String {
    let up = fs::read_to_string("/proc/uptime").unwrap_or_default();
    let up = up.split_whitespace().next().unwrap_or("?").to_owned();
    format!("{} up={up} {line}", wall_now())
}

/// Append one line, moving a full log to `keeper.log.1` first.
fn append(dir: &Path, text: &str, cap: u64) {
    let path = dir.join("keeper.log");
    let _ = fs::create_dir_all(dir);
    if fs::metadata(&path).is_ok_and(|meta| meta.len() > cap) {
        let _ = fs::rename(&path, dir.join("keeper.log.1"));
    }
    if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(file, "{text}");
    }
}

fn arg(args: &[String], name: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_default()
}

fn guard(args: &[String]) -> i32 {
    let token = arg(args, "--token");
    let seconds: u64 = arg(args, "--seconds").parse().unwrap_or(180);
    let ip_proto = arg(args, "--ip-proto");
    let absent = args.iter().any(|item| item == "--absent");
    if token.is_empty() || ip_proto.is_empty() {
        eprintln!("guard needs --token and --ip-proto");
        return 64;
    }
    thread::sleep(Duration::from_secs(seconds));
    let confirm = fs::read_to_string(state().join(format!("confirm-{token}"))).unwrap_or_default();
    if confirm.trim() == token {
        let _ = fs::remove_file(state().join("pending.json"));
        log("guard: management returned; keeping the new prefix-delegation setting");
        return 0;
    }
    log("guard: management did not return; restoring the previous prefix-delegation setting");
    let pending = Pending {
        token,
        ip_proto,
        absent,
        not_before: 0,
    };
    if finish_revert(&pending) {
        0
    } else {
        log("guard: could not restore ip_proto");
        1
    }
}

fn confirm(args: &[String]) -> i32 {
    let token = arg(args, "--token");
    if token.is_empty() {
        return 64;
    }
    // Monotonic time: an NTP step during the window (sqn-date steps the clock)
    // must not end it early and revert a working setting, or stretch it.
    let start = Instant::now();
    let mut saw_down = false;
    let mut up_since: Option<Instant> = None;
    while start.elapsed() < Duration::from_secs(150) {
        let up = mgmt_up();
        if !up {
            saw_down = true;
            up_since = None;
        } else {
            let since = *up_since.get_or_insert_with(Instant::now);
            // A bearer that never drops means the re-attach did not happen. Confirming
            // then would keep a new setting that the guard is supposed to revert.
            let stable = since.elapsed() >= Duration::from_secs(20);
            if saw_down && stable {
                let _ = fs::create_dir_all(state());
                if fs::write(state().join(format!("confirm-{token}")), &token).is_ok() {
                    log("confirm: management bearer is back");
                    return 0;
                }
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
    log("confirm: management bearer did not settle");
    1
}

fn mgmt_up() -> bool {
    fs::read_to_string("/sys/class/net/lte0pdn0/carrier").is_ok_and(|value| value.trim() == "1")
        && Command::new("ip")
            .args(["-4", "addr", "show", "dev", "lte0pdn0"])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("inet "))
}

fn nvram() -> PathBuf {
    env::var("TITAN_NVRAM").map_or_else(
        |_| PathBuf::from("/usr/lib/titan-api/titan-nvram"),
        PathBuf::from,
    )
}

pub(crate) fn nvram_set(key: &str, value: &str) -> Result<(), ()> {
    let mut child = Command::new(nvram())
        .args(["set", "0", key])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| ())?;
    child
        .stdin
        .take()
        .ok_or(())?
        .write_all(value.as_bytes())
        .map_err(|_| ())?;
    child
        .wait()
        .ok()
        .filter(|status| status.success())
        .map(|_| ())
        .ok_or(())
}

fn nvram_commit() -> Result<(), ()> {
    Command::new(nvram())
        .args(["commit", "0"])
        .status()
        .ok()
        .filter(|status| status.success())
        .map(|_| ())
        .ok_or(())
}

pub(crate) fn signal_rcinit() -> Result<(), ()> {
    let entries = fs::read_dir("/proc").map_err(|_| ())?;
    for entry in entries.flatten() {
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if fs::read_to_string(entry.path().join("comm")).is_ok_and(|name| name.trim() == "rcinit") {
            return (unsafe { libc::kill(pid, libc::SIGUSR1) } == 0)
                .then_some(())
                .ok_or(());
        }
    }
    Err(())
}

/// Install the egress filter and take it off again. A second process removes it
/// if this one does not finish, so a probe cannot black-hole the port.
fn filter_probe() -> i32 {
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

fn filter_undo(args: &[String]) -> i32 {
    let dev = args.first().map(String::as_str).unwrap_or("eth0");
    thread::sleep(Duration::from_secs(30));
    if fs::read_to_string("/tmp/titan-pd-filter-probe.done").is_err() {
        let _ = run::tc_apply(&titan_pd_model::filter::remove(dev));
        log("filter probe safety timer removed the egress filter");
    }
    0
}

fn spawn_undo(dev: &str) -> Result<(), ()> {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    let exe = env::current_exe().map_err(|_| ())?;
    let mut child = Command::new(exe);
    child
        .arg("filter-undo")
        .arg(dev)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        child.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    child.spawn().map(|_| ()).map_err(|_| ())?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_arguments_are_positional_flags() {
        let args = ["--token", "abc", "--seconds", "180", "--ip-proto", "2"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(arg(&args, "--token"), "abc");
        assert_eq!(arg(&args, "--ip-proto"), "2");
        assert_eq!(arg(&args, "--missing"), "");
    }
}
