//! The self-revert pair for a setting change that re-attaches LTE: `guard`
//! puts the old setting back unless `confirm` recorded that management
//! returned, and a keeper that starts after a reboot finishes what a lost
//! guard left pending.

use std::env;
use std::fs;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use titan_pd_model::config::{self, Pending, Recovery};

use crate::clock::unix_now;
use crate::paths::{runtime_dir, state_dir};
use crate::{log, nvram};

/// The guard process did not survive (a reboot kills it). Put the previous
/// setting back once, after commit and before the re-attach, so a crash in the
/// re-attach cannot loop. The decision uses the boot, not the wall clock: the
/// unit boots in 2013 until NTP answers (see `config::recovery`).
pub fn recover_pending() {
    let first = note_boot();
    let path = state_dir().join("pending.json");
    let Ok(Some(pending)) = config::load_pending(&path) else {
        return;
    };
    let confirm_file =
        fs::read_to_string(state_dir().join(format!("confirm-{}", pending.token))).unwrap_or_default();
    let decision = config::recovery(
        guard_running(),
        config::confirmed(&pending.token, &confirm_file),
        first,
        unix_now(),
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
    let marker = runtime_dir().join("boot-id");
    let seen = fs::read_to_string(&marker).ok();
    let first = config::first_start(seen.as_deref(), &boot_id);
    if first {
        let _ = fs::create_dir_all(runtime_dir());
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
        let _ = fs::remove_file(state_dir().join("config.json"));
    } else if let Err(err) =
        fs::rename(state_dir().join("config.previous"), state_dir().join("config.json"))
    {
        log(&format!("could not restore the setting file: {err}"));
    }
    if nvram::set("ip_proto", &pending.ip_proto).is_err()
        || nvram::set("sqns_admin_apply", "1").is_err()
        || nvram::commit().is_err()
    {
        return false;
    }
    let _ = fs::remove_file(state_dir().join("pending.json"));
    let _ = nvram::signal_rcinit();
    true
}

fn arg(args: &[String], name: &str) -> String {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .unwrap_or_default()
}

pub fn guard(args: &[String]) -> i32 {
    let token = arg(args, "--token");
    let seconds: u64 = arg(args, "--seconds").parse().unwrap_or(180);
    let ip_proto = arg(args, "--ip-proto");
    let absent = args.iter().any(|item| item == "--absent");
    if token.is_empty() || ip_proto.is_empty() {
        eprintln!("guard needs --token and --ip-proto");
        return 64;
    }
    thread::sleep(Duration::from_secs(seconds));
    let confirm = fs::read_to_string(state_dir().join(format!("confirm-{token}"))).unwrap_or_default();
    if confirm.trim() == token {
        let _ = fs::remove_file(state_dir().join("pending.json"));
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

pub fn confirm(args: &[String]) -> i32 {
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
                let _ = fs::create_dir_all(state_dir());
                if fs::write(state_dir().join(format!("confirm-{token}")), &token).is_ok() {
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

pub fn mgmt_up() -> bool {
    fs::read_to_string("/sys/class/net/lte0pdn0/carrier").is_ok_and(|value| value.trim() == "1")
        && Command::new("ip")
            .args(["-4", "addr", "show", "dev", "lte0pdn0"])
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("inet "))
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
