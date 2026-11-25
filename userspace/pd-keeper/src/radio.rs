//! Operator JSON interface and the supervisor for volatile radio settings.
//! Only the guard starts mutation workers. Its monotonic deadline covers the
//! whole worker process group, including vendor programs that stop responding.
//!
//! Applying or removing a profile never cycles the radio. A carrier cap
//! written while attached waits for the next attach. The only radio cycles
//! are the opt-in enforcement re-attach (`titan_pd_model::radio::cycle_gate`)
//! and the carrier picker's visits. Every one waits out the CPAS window and
//! for a set clock, and fits a daily cap (`titan_pd_model::radio_guard`).
//!
//! When the guard tries, judges and retries a profile is decided in
//! `titan_pd_model::radio_guard` (v1.0.17): no transient condition (a tower
//! outage, a boot in the CPAS window, a power cut, a busy console, a lost
//! ping) keeps a profile off for longer than its backoff, and only a
//! comparison with stock settings counts against it. Every worker that drives
//! the modem console holds it (`console_lock`) for its whole run.
use crate::{
    carrier_pick_io,
    clock::{monotonic, unix_now},
    console_lock,
    files::read_file,
    nvram,
    radio_modem::{cfun, console, media},
    radio_sqm,
};
use serde_json::{Value, json};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    mem::discriminant,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Condvar, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};
use titan_pd_model::{
    carrier_pick::{self as pick, Arm, Measure, Record},
    config::persistent_volume_mounted,
    radio::{self as model, Action, Cell, PCELL_CLEAR, PCELL_QUERY, Picker, Profile, failures},
    radio_guard::{self as guard_model, Health, Restore, Retry, Verdict},
    reboots,
};
use titan_sys::process::{Signal, SpawnExt, effective_uid, kill_group};

/// Seconds between health and carrier checks while a profile is active.
const CHECK_EVERY: u64 = 30;
/// After an attach, re-check the carrier state this soon.
const AFTER_ATTACH: u64 = 20;
/// Fallback poll period when no radio profile is configured.
const IDLE_SUPERVISE_SECS: u64 = 60;
/// A worker that drives the modem console may first wait this long for it.
const CONSOLE_WAIT: u64 = console_lock::RADIO_WAIT.as_secs();
/// Worker deadlines, with the console wait where the worker waits for it.
const PREFLIGHT_SECS: u64 = 60;
const APPLY_SECS: u64 = 180 + CONSOLE_WAIT;
const CHECK_SECS: u64 = 35 + console_lock::CHECK_WAIT.as_secs();
const JUDGE_SECS: u64 = guard_model::JUDGE_SECS + 30;
const ROLLBACK_SECS: u64 = 120 + CONSOLE_WAIT;
const ENFORCE_SECS: u64 = 170 + CONSOLE_WAIT;
const PICK_CYCLE_SECS: u64 = 175 + CONSOLE_WAIT;
const RESTORE_LOG_SECS: u64 = 15 + CONSOLE_WAIT;
/// A worker's management failures, which the guard compares with stock: the
/// confirm never settled, or a check found management not answering.
const NOT_SETTLED: &str = "management failed to settle";
const UNREACHABLE: &str = "management unreachable";
/// The RRC counter would not read: not judged.
const MISSING_COUNTER: &str = "missing RRC counter";
/// A worker found a condition gone right before acting, and did nothing.
const NOT_NOW: &str = "not now: ";
/// Left in the keeper's RAM directory when a stock restore keeps failing: the
/// keeper restarts the unit through its reboot gate (`run/radio_reboot.rs`).
pub const REBOOT_REQUEST: &str = "radio-reboot";

fn profile_signal() -> &'static (Mutex<u64>, Condvar) {
    static SIGNAL: OnceLock<(Mutex<u64>, Condvar)> = OnceLock::new();
    SIGNAL.get_or_init(|| (Mutex::new(0), Condvar::new()))
}

fn wake_supervisor() {
    let (lock, cvar) = profile_signal();
    if let Ok(mut seq) = lock.lock() {
        *seq = seq.wrapping_add(1);
        cvar.notify_all();
    }
}

const DISK: &str = "/mnt/titan-api/radio";
/// The radio files on the persistent volume (`TITAN_RADIO_DIR` in tests).
fn disk_dir() -> PathBuf {
    crate::paths::env_path_or("TITAN_RADIO_DIR", DISK)
}
fn disk(name: &str) -> PathBuf {
    disk_dir().join(name)
}
/// The keeper's private RAM directory (`TITAN_PD_RUNTIME` in tests).
fn ram(name: &str) -> PathBuf {
    crate::paths::runtime_dir().join(name)
}
/// The persistent volume holds the radio files (tests name a directory).
fn volume_ready() -> bool {
    std::env::var_os("TITAN_RADIO_DIR").is_some() || persistent_volume_mounted()
}
fn fail(s: &str) -> io::Error {
    io::Error::other(s.to_owned())
}
fn not_now(why: &str) -> io::Error {
    fail(&format!("{NOT_NOW}{why}"))
}
fn pause(n: u64) {
    thread::sleep(Duration::from_secs(n));
}

fn atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if path.starts_with(disk_dir()) {
        root()?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(tmp, path)?;
    File::open(path.parent().unwrap())?.sync_all()
}
fn store(path: &Path, p: &Profile) -> io::Result<()> {
    atomic(path, &serde_json::to_vec(p)?)
}
fn profile(path: &Path) -> io::Result<Profile> {
    match fs::read(path) {
        Ok(data) => Profile::parse(&data).map_err(fail),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Profile::default()),
        Err(e) => Err(e),
    }
}
/// The stamp of the strike record: the profile's id and this firmware's.
fn stamp(p: &Profile) -> io::Result<(String, String)> {
    static FIRMWARE: OnceLock<String> = OnceLock::new();
    Ok((
        guard_model::profile_id(&serde_json::to_vec(p)?),
        FIRMWARE.get_or_init(crate::paths::firmware_id).clone(),
    ))
}
/// The strike record as it applies to `p` (`radio_guard::parse_record`). A
/// missing, older or unreadable file reads as none; the next trial rewrites it.
fn strikes(p: &Profile) -> io::Result<guard_model::Record> {
    let (id, firmware) = stamp(p)?;
    Ok(guard_model::parse_record(
        &read_file(disk("strikes")),
        &id,
        &firmware,
    ))
}
fn store_strikes(p: &Profile, record: guard_model::Record) -> io::Result<()> {
    let (id, firmware) = stamp(p)?;
    atomic(
        &disk("strikes"),
        guard_model::render_record(record, &id, &firmware).as_bytes(),
    )
}
/// When `p` may be tried next on this boot (RAM, so a restarted guard keeps
/// it). A boot starts from the record's trials that were never judged.
fn retry(p: &Profile) -> io::Result<Retry> {
    let (id, _) = stamp(p)?;
    let tries = strikes(p)?.tries;
    Ok(Retry::parse(&read_file(ram("radio-retry")))
        .filter(|r| r.profile == id)
        .unwrap_or_else(|| Retry::new(&id, tries)))
}
fn store_retry(r: &Retry) -> io::Result<()> {
    atomic(&ram("radio-retry"), r.render().as_bytes())
}
fn status(phase: &str, detail: &str) -> io::Result<()> {
    atomic(
        &ram("radio-status"),
        json!({"phase":phase,"detail":detail})
            .to_string()
            .as_bytes(),
    )
}
fn json_file(name: &str) -> Value {
    fs::read(ram(name))
        .ok()
        .and_then(|v| serde_json::from_slice(&v).ok())
        .unwrap_or(Value::Null)
}
/// Wait for the persistent volume: it may mount after the keeper starts.
/// Before v1.0.17 a late mount kept every radio profile off for the boot.
fn wait_for_volume() {
    while !volume_ready() {
        thread::sleep(Duration::from_secs(IDLE_SUPERVISE_SECS));
    }
}

pub fn supervise() {
    thread::spawn(|| {
        wait_for_volume();
        if let Err(e) = listen() {
            eprintln!("radio profile API: {e}");
        }
    });
    thread::spawn(|| {
        wait_for_volume();
        let mut seen = 0u64;
        loop {
            // No profile on a stock installation. Only inspect the filesystem.
            let active = disk("profile.json").exists() || ram("radio-journal").exists();
            if active {
                let _ = Command::new(ram("titan-pd-keeper"))
                    .arg("opt-guard")
                    .stdin(Stdio::null())
                    .status();
            }
            let wait = Duration::from_secs(if active { 5 } else { IDLE_SUPERVISE_SECS });
            let (lock, cvar) = profile_signal();
            if let Ok(guard) = lock.lock() {
                let guard = if *guard == seen {
                    match cvar.wait_timeout(guard, wait) {
                        Ok((guard, _)) => guard,
                        Err(poisoned) => poisoned.into_inner().0,
                    }
                } else {
                    guard
                };
                seen = *guard;
            } else {
                thread::sleep(wait);
            }
        }
    });
}

fn root() -> io::Result<()> {
    if effective_uid() != 0 {
        return Err(fail("operator access required"));
    }
    if !volume_ready() {
        return Err(fail("persistent volume unavailable"));
    }
    Ok(())
}

fn private_runtime() -> io::Result<()> {
    let md = fs::symlink_metadata(crate::paths::runtime_dir())?;
    if !md.is_dir() || md.uid() != 0 || md.mode() & 0o077 != 0 {
        return Err(fail("untrusted keeper runtime directory"));
    }
    Ok(())
}

fn request(input: &[u8]) -> io::Result<Value> {
    let message: Value = serde_json::from_slice(input)?;
    match message["op"].as_str() {
        Some("get") => Ok(serde_json::to_value(profile(&disk("profile.json"))?)?),
        Some("set") => {
            let p = Profile::parse(&serde_json::to_vec(&message["profile"])?).map_err(fail)?;
            fs::create_dir_all(disk_dir())?;
            store(&disk("profile.json"), &p)?;
            // A saved profile, even the same one again, starts with fresh
            // trials: the visible way to clear a lock.
            rm(disk("strikes"))?;
            rm(ram("radio-retry"))?;
            wake_supervisor();
            Ok(json!({"accepted":true}))
        }
        Some("status") => {
            let mut guard = json_file("radio-status");
            if guard.is_null() {
                guard = json!({"phase":"off","detail":"no trial this boot"});
            }
            let record = strikes(&profile(&disk("profile.json")).unwrap_or_default()).ok();
            Ok(json!({
                "guard":guard,
                "strikes":record.map(|r| r.strikes),
                "unjudged_trials":record.map(|r| r.tries),
                "counters":json_file("radio-counters"),
                "carriers":json_file("radio-carriers"),
                "pick":json_file("radio-pick"),
            }))
        }
        Some("survey") => {
            if profile(&disk("profile.json"))?.picker().is_none() {
                return Err(fail("no carrier picker in the saved profile"));
            }
            atomic(&ram("pick-survey-now"), b"1")?;
            Ok(json!({"survey":"requested"}))
        }
        _ => Err(fail("invalid profile operation")),
    }
}

// One bounded JSON document per connection, framed by a write half-close.
// The existing root-only keeper directory protects both bind and connect.
fn listen() -> io::Result<()> {
    root()?;
    private_runtime()?;
    let path = ram("radio.sock");
    rm(path.clone())?;
    let listener = UnixListener::bind(path)?;
    for sock in listener.incoming() {
        let mut sock = sock?;
        sock.set_read_timeout(Some(Duration::from_secs(3)))?;
        sock.set_write_timeout(Some(Duration::from_secs(3)))?;
        let mut bytes = vec![];
        let res = Read::by_ref(&mut sock)
            .take(8193)
            .read_to_end(&mut bytes)
            .and_then(|n| {
                if n > 8192 {
                    Err(fail("request too large"))
                } else {
                    request(&bytes)
                }
            });
        let response = match res {
            Ok(v) => json!({"result":v}),
            Err(e) => json!({"error":e.to_string()}),
        };
        let _ = writeln!(sock, "{response}");
    }
    Ok(())
}

pub fn api(op: Option<&str>) -> io::Result<()> {
    root()?;
    private_runtime()?;
    let message = match op {
        Some("get" | "status" | "survey") => json!({"op":op}),
        Some("set") => {
            let mut bytes = vec![];
            io::stdin().take(4097).read_to_end(&mut bytes)?;
            let p = Profile::parse(&bytes).map_err(fail)?;
            json!({"op":"set","profile":p})
        }
        _ => return Err(fail("usage: radio-profile get|set|status|survey")),
    };
    let mut s = UnixStream::connect(ram("radio.sock"))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.write_all(message.to_string().as_bytes())?;
    s.shutdown(std::net::Shutdown::Write)?;
    let reply: Value = serde_json::from_reader(s.take(16384))?;
    if let Some(e) = reply["error"].as_str() {
        return Err(fail(e));
    }
    println!("{}", reply["result"]);
    Ok(())
}

fn run_worker(op: &str, seconds: u64) -> io::Result<()> {
    let target = if op == "apply" {
        Some(profile(&ram("radio-target"))?)
    } else {
        None
    };
    let mut cmd = Command::new(ram("titan-pd-keeper"));
    cmd.args(["radio-worker", op])
        .stdin(Stdio::null())
        .process_group(0)
        // The worker dies with the guard, and does not start once it is gone.
        .die_with_parent(std::process::id());
    let reason = ram("radio-worker-error");
    cmd.stderr(Stdio::from(File::create(&reason)?));
    let mut child = cmd.spawn()?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        if let Some(exit) = child.try_wait()? {
            if exit.success() {
                return Ok(());
            }
            let detail = fs::read_to_string(&reason).unwrap_or_default();
            let cause = detail
                .lines()
                .last()
                .and_then(|l| l.strip_prefix("radio-worker: "))
                .unwrap_or("worker failed");
            return Err(fail(cause));
        }
        if let Some(ref target) = target {
            if profile(&disk("profile.json")).ok().as_ref() != Some(target)
                || ram("stopped").exists()
            {
                break;
            }
        }
        pause(1);
    }
    let _ = kill_group(child.id() as i32, Signal::Kill);
    child.wait()?;
    Err(fail("worker deadline expired"))
}
fn rm(path: PathBuf) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        r => r,
    }
}
pub fn transition_in_progress(now: u64) -> bool {
    fs::read_to_string(ram("radio-transition"))
        .ok()
        .and_then(|deadline| deadline.parse::<u64>().ok())
        .is_some_and(|until| until > now && until - now <= 185)
}
fn transition(seconds: u64) -> io::Result<()> {
    let until = crate::clock::monotonic() + seconds;
    atomic(&ram("radio-transition"), until.to_string().as_bytes())
}

/// Put stock settings back wherever a profile's are in place. False while
/// the restore still fails: it is tried again after its backoff
/// (`radio_guard::Restore`), and once it has failed for
/// `RESTORE_RESTART_SECS` the keeper is asked for a restart, which its
/// reboot gate times (never in the CPAS window). The saved profile is never
/// touched. Before v1.0.17 one failed restore overwrote the operator's profile
/// with an empty one and rebooted at once, at any hour.
fn to_stock() -> io::Result<bool> {
    rm(ram("radio-active"))?;
    if !ram("radio-journal").exists() {
        // A query cut short may have left the console logging.
        if ram("radio-console-open").exists() {
            let _ = run_worker("restore-log", RESTORE_LOG_SECS);
        }
        rm(ram("radio-transition"))?;
        restored()?;
        return Ok(true);
    }
    let now = monotonic();
    let mut restore = Restore::parse(&read_file(ram("radio-restore")));
    if !restore.due(now) {
        return Ok(false);
    }
    status("reverting", "restoring stock settings")?;
    let error = match run_worker("rollback", ROLLBACK_SECS) {
        Ok(()) => {
            rm(ram("radio-journal"))?;
            rm(ram("radio-transition"))?;
            restored()?;
            return Ok(true);
        }
        Err(e) => e,
    };
    let wait = restore.failed(now);
    atomic(&ram("radio-restore"), restore.render().as_bytes())?;
    let mut detail = format!(
        "stock restore failed {} times in a row ({error}); trying again in {wait} s",
        restore.failures
    );
    if restore.restart_due(now) {
        if !ram(REBOOT_REQUEST).exists() {
            // A restart puts modem RAM and the qdiscs back to stock. The
            // profile counts one more unjudged trial, so after the restart
            // it waits its backoff before it is tried again.
            if let Ok(target) = profile(&ram("radio-target")) {
                if let Ok(record) = strikes(&target) {
                    let _ = store_strikes(&target, record.started());
                }
            }
            atomic(&ram(REBOOT_REQUEST), b"radio\n")?;
            crate::log(&format!(
                "radio profile: {detail}; asking the keeper for a restart, which waits out the SAS CPAS window"
            ));
        }
        detail.push_str("; a restart is asked for, and the keeper's reboot gate decides when");
    }
    status("recovery", &detail)?;
    Ok(false)
}

/// Stock settings are back: forget a failed restore and the restart it asked
/// for.
fn restored() -> io::Result<()> {
    rm(ram("radio-restore"))?;
    rm(ram(REBOOT_REQUEST))
}

fn lock_guard() -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(ram("radio.lock"))?;
    // flock(LOCK_EX | LOCK_NB), held until the file is closed.
    if file.try_lock().is_err() {
        return Err(fail("guard already running"));
    }
    Ok(file)
}

pub fn guard() -> io::Result<()> {
    root()?;
    private_runtime()?;
    let _lock = lock_guard()?;
    resume()?;
    let mut watch = CarrierWatch::default();
    let mut picker = PickWatch::new();
    let mut health = Health::default();
    loop {
        if ram("stopped").exists() {
            // The keeper is stopping: stock settings first, then exit.
            if to_stock()? {
                return Ok(());
            }
            pause(5);
            continue;
        }
        let Ok(desired) = profile(&disk("profile.json")) else {
            to_stock()?;
            status("blocked", "invalid saved profile")?;
            pause(10);
            continue;
        };
        if desired.picker().is_none() {
            // No stale picker state in the status once the picker is gone.
            rm(ram("radio-pick"))?;
            rm(ram("radio-pick-back"))?;
        }
        if desired.actions.is_empty() {
            if to_stock()? {
                rm(disk("strikes"))?;
                rm(ram("radio-retry"))?;
                if json_file("radio-status")["phase"] != "off" {
                    status("off", "stock")?;
                }
            }
            pause(5);
            continue;
        }
        if desired == profile(&ram("radio-active"))? {
            if let Err(failure) = steady(&desired, &mut watch, &mut picker, &mut health) {
                fall_back(&desired, &failure)?;
                watch = CarrierWatch::default();
                picker = PickWatch::new();
                health = Health::default();
            }
        } else if trial(&desired)? {
            watch = CarrierWatch::default();
            picker = PickWatch::new();
            health = Health::default();
        }
        pause(5);
    }
}

/// A guard restarted on the same boot. A profile it confirmed keeps running
/// and is checked as usual. Anything cut short in the middle (an apply, a
/// radio cycle, a restore) goes back to stock, and the profile is tried again
/// after a backoff, so a guard that keeps dying cannot loop. Before v1.0.17
/// any restart turned the profile off for the rest of the boot.
fn resume() -> io::Result<()> {
    rm(ram("radio-blocked"))?;
    if !ram("radio-journal").exists() {
        return Ok(());
    }
    let journal = profile(&ram("radio-journal")).ok();
    let kept = journal.as_ref().is_some_and(|j| !j.actions.is_empty())
        && journal == profile(&ram("radio-active")).ok()
        && !ram("radio-transition").exists();
    if kept {
        crate::log_ram("radio profile: guard restarted; the confirmed profile keeps running");
        return Ok(());
    }
    let target = profile(&ram("radio-target")).unwrap_or_default();
    if !target.actions.is_empty() {
        let mut next = retry(&target)?;
        next.failed(monotonic());
        store_retry(&next)?;
    }
    to_stock()?;
    status("reverted", "interrupted; trying again after a backoff")
}

/// Why a running profile, or a trial, failed: the worker's error, and whether
/// management failed, which is compared with stock settings.
struct Failure {
    error: io::Error,
    management: bool,
}

/// A worker result that says nothing about the profile: the console was
/// busy, the RRC counter would not read, or a condition no longer held right
/// before acting.
fn no_verdict(e: &io::Error) -> bool {
    let cause = e.to_string();
    console_lock::busy(e) || cause == MISSING_COUNTER || cause.starts_with(NOT_NOW)
}

/// Try the saved profile once its turn has come. True once it is confirmed.
fn trial(p: &Profile) -> io::Result<bool> {
    // A profile half put back goes all the way to stock first.
    if ram("radio-journal").exists() && !ram("radio-active").exists() && !to_stock()? {
        return Ok(false);
    }
    let record = strikes(p)?;
    if record.locked() {
        to_stock()?;
        if json_file("radio-status")["phase"] != "locked" {
            status(
                "locked",
                "management failed under this profile three times in a row while stock settings kept it; saving the profile again, or a new firmware, clears this",
            )?;
        }
        return Ok(false);
    }
    let now = monotonic();
    let mut retry = retry(p)?;
    if !retry.due(now) {
        if !ram("radio-status").exists() {
            status(
                "waiting",
                &format!(
                    "{} earlier trials were cut short; the next starts {} s after boot",
                    record.tries, retry.next_at
                ),
            )?;
        }
        return Ok(false);
    }
    // Stock settings (or the profile this one replaces) must work first.
    // Otherwise nothing is tried or counted: a tower or core outage, a boot in
    // the CPAS window or a slow LTE stack only delays the trial.
    if let Err(e) = run_worker("preflight", PREFLIGHT_SECS) {
        retry.not_ready(now);
        store_retry(&retry)?;
        let detail = format!("not tried: {e}");
        if json_file("radio-status")["detail"] != detail.as_str() {
            status("waiting", &detail)?;
        }
        return Ok(false);
    }
    fs::create_dir_all(disk_dir())?;
    store(&ram("radio-target"), p)?;
    // Counted before the first write, so a trial cut short (a power cut, a
    // crash) still spaces the next one.
    store_strikes(p, record.started())?;
    status("applying", "waiting for profile confirmation")?;
    let before = profile(&ram("radio-journal")).ok();
    let applied = run_worker("apply", APPLY_SECS);
    let now = monotonic();
    let error = match applied {
        Ok(()) => {
            store(&ram("radio-active"), p)?;
            store_strikes(p, guard_model::Record::default())?;
            rm(ram("radio-retry"))?;
            status("active", "confirmed")?;
            crate::log("radio profile: confirmed");
            return Ok(true);
        }
        Err(e) => e,
    };
    // The apply writes its journal right before its first write.
    if profile(&ram("radio-journal")).ok() == before {
        // Nothing reached the modem or the qdiscs: no trial, and not counted.
        store_strikes(p, record)?;
        let wait = if no_verdict(&error) {
            retry.not_ready(now);
            guard_model::NOT_READY_SECS
        } else {
            retry.failed(now)
        };
        store_retry(&retry)?;
        status("waiting", &format!("not tried: {error}; trying again in {wait} s"))?;
        return Ok(false);
    }
    let management = error.to_string() == NOT_SETTLED;
    fall_back(p, &Failure { error, management })?;
    Ok(false)
}

/// One look at the running profile. `Err` when it must go: a failure of its
/// own, or management lost for `SUSTAINED_SECS` while attached.
fn steady(
    p: &Profile,
    watch: &mut CarrierWatch,
    picker: &mut PickWatch,
    health: &mut Health,
) -> Result<(), Failure> {
    let now = monotonic();
    let attached = media() == "ATTACHED";
    if !attached {
        health.detached();
    }
    if watch.due(now, attached) {
        match run_worker("check", CHECK_SECS) {
            Ok(()) if attached => {
                if health.failing_for(now).is_some() {
                    let _ = status("active", "management answers again");
                }
                health.observe(now, Some(true));
            }
            Ok(()) => {}
            Err(e) if e.to_string() == UNREACHABLE => {
                if health.observe(now, Some(false)) {
                    let error = fail(&format!(
                        "{UNREACHABLE} for {} s while attached",
                        guard_model::SUSTAINED_SECS
                    ));
                    return Err(Failure {
                        error,
                        management: true,
                    });
                }
                let _ = status(
                    "active",
                    &format!(
                        "management not answering for {} s; stock settings go back only after {} s",
                        health.failing_for(now).unwrap_or(0),
                        guard_model::SUSTAINED_SECS
                    ),
                );
                return Ok(());
            }
            Err(e) if no_verdict(&e) => {}
            Err(error) => {
                return Err(Failure {
                    error,
                    management: false,
                });
            }
        }
        match watch.carriers(p, now) {
            Err(error) if !no_verdict(&error) => {
                return Err(Failure {
                    error,
                    management: false,
                });
            }
            _ => {}
        }
    }
    if let Some(pk) = p.picker() {
        match picker.tick(&pk) {
            Err(error) if !no_verdict(&error) => {
                return Err(Failure {
                    error,
                    management: false,
                });
            }
            _ => {}
        }
    }
    Ok(())
}

/// The running profile, or a trial, failed. Stock settings go back; a
/// management failure is then compared with stock settings
/// (`radio_guard::Verdict`), and the profile is tried again after its backoff.
fn fall_back(p: &Profile, failure: &Failure) -> io::Result<()> {
    let restored = to_stock()?;
    let judged = if !restored {
        "stock settings are not back yet, so nothing is judged".to_owned()
    } else {
        let verdict = if failure.management {
            Verdict::of(true, run_worker("judge", JUDGE_SECS).is_ok())
        } else {
            Verdict::Unjudged
        };
        let record = strikes(p)?.judged(verdict);
        store_strikes(p, record)?;
        if record.locked() {
            format!("{}; locked after {} strikes", verdict.describe(), record.strikes)
        } else {
            verdict.describe().to_owned()
        }
    };
    let mut next = retry(p)?;
    let wait = next.failed(monotonic());
    store_retry(&next)?;
    let detail = format!("{}; {judged}; trying again in {wait} s", failure.error);
    crate::log(&format!("radio profile: stock settings back: {detail}"));
    status("reverted", &detail)
}

/// When to check, and how long the tower has held more carriers than the cap.
#[derive(Default)]
struct CarrierWatch {
    last_check: Option<u64>,
    attached: bool,
    after_attach: Option<u64>,
    over_since: Option<u64>,
    over_logged: Option<u64>,
}

impl CarrierWatch {
    fn due(&mut self, now: u64, attached: bool) -> bool {
        // The cap applies at an attach and the tower may add a carrier after
        // it, so look again shortly after every attach and then periodically.
        if attached && !self.attached {
            self.after_attach = Some(now + AFTER_ATTACH);
        }
        self.attached = attached;
        let after_attach = self.after_attach.is_some_and(|t| now >= t);
        if after_attach
            || self
                .last_check
                .is_none_or(|t| now.saturating_sub(t) >= CHECK_EVERY)
        {
            self.after_attach = None;
            self.last_check = Some(now);
            return true;
        }
        false
    }

    fn carriers(&mut self, p: &Profile, now: u64) -> io::Result<()> {
        let Some((cap, cycle_hours, _)) = p.carrier_cap() else {
            return rm(ram("radio-carriers"));
        };
        let attached = media() == "ATTACHED";
        let carriers = model::carriers(&nvram::read_value("sqns_connection_sccInfo"));
        let over = attached && carriers.is_some_and(|n| n > cap);
        if !over {
            self.over_since = None;
        } else if self.over_since.is_none() {
            self.over_since = Some(now);
            // keeper.log is on flash: at most one line an hour for this.
            if self.over_logged.is_none_or(|t| now.saturating_sub(t) >= 3600) {
                self.over_logged = Some(now);
                crate::log(&format!(
                    "radio profile: the tower holds {} carriers over the {cap}-carrier cap; {}",
                    carriers.unwrap_or(0),
                    if cycle_hours.is_some() {
                        "an enforcement re-attach may follow when its conditions hold"
                    } else {
                        "enforcement re-attach is off, so the cap waits for the next attach"
                    }
                ));
            }
        }
        let last_cycle = last_cycle();
        let mode_grant = nvram::read_value("cbrs_mode_grant");
        let grant_state = nvram::read_value("cbrs_grant_state");
        let verdict = model::cycle_gate(model::Gate {
            cap,
            cycle_hours,
            carriers,
            attached,
            over_since: self.over_since,
            last_cycle,
            now,
            mode_grant: &mode_grant,
            grant_state: &grant_state,
            hold: cycle_hold(),
        });
        // The daily cap of radio cycles, once everything else holds.
        let blocked = match verdict {
            Err(why) => Some(why.to_owned()),
            Ok(()) => cycle_cap(reboots::SLOTS_AWAY),
        };
        atomic(
            &ram("radio-carriers"),
            json!({
                "cap":cap,
                "carriers":carriers,
                "over_cap_seconds":self.over_since.map(|t| now.saturating_sub(t)),
                "last_cycle_uptime":last_cycle,
                "enforcement":blocked.as_deref().unwrap_or("due"),
            })
            .to_string()
            .as_bytes(),
        )?;
        if blocked.is_none() {
            status("enforcing", "re-attaching once to enforce the carrier cap")?;
            run_worker("enforce", ENFORCE_SECS)?;
            self.over_since = None;
            status("active", "confirmed")?;
        }
        Ok(())
    }
}

fn last_cycle() -> u64 {
    fs::read_to_string(ram("radio-last-cycle"))
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0)
}

fn ready() -> bool {
    nvram::read_value("sqns_identity_boardName") == "GDM7243AP-ODU-E-B48"
        && fs::metadata("/var/tmp/lted-daemon").is_ok_and(|m| m.file_type().is_socket())
        && ["lted", "lteatcm", "ucid"].iter().all(|name| {
            Command::new("pidof")
                .arg(name)
                .stdout(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
        && matches!(media().as_str(), "ATTACHED" | "DETACHED" | "SEARCHING")
}
// A SAS grant loss is not caused by a profile that never cycles the radio,
// so it neither blocks confirmation nor rolls the profile back. The
// enforcement cycle has its own grant gate.
fn reachable(p: &Profile) -> bool {
    media() == "ATTACHED"
        && crate::revert::mgmt_up()
        && p.management_probe.is_some_and(|ip| {
            Command::new("ping")
                .args(["-I", "lte0pdn0", "-c", "1", "-W", "2", &ip.to_string()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
}
fn current(a: &Action, stock: bool) -> io::Result<bool> {
    let reply = console(a.query().ok_or_else(|| fail("no modem query"))?)?;
    Ok(a.matches_reply(&reply, stock))
}
fn set(a: &Action, stock: bool) -> io::Result<()> {
    console(&a.command(stock).ok_or_else(|| fail("no modem action"))?)?;
    if !current(a, stock)? {
        return Err(fail("radio read-back failed"));
    }
    Ok(())
}
fn count() -> io::Result<u32> {
    // The worker holds the console (`console_lock`), so a flag session can no
    // longer cut a reply short, as one did on the bench (2026-11-24). Three
    // misses in a row are a missing counter, which the guard does not judge.
    for attempt in 0..3 {
        if let Some(n) = console("rrc dm reest stat ?").ok().and_then(|r| failures(&r)) {
            return Ok(n);
        }
        if attempt < 2 {
            pause(3);
        }
    }
    Err(fail(MISSING_COUNTER))
}
fn rates(p: &Profile) -> Option<(u32, u32)> {
    p.actions.iter().find_map(|a| {
        if let Action::Sqm {
            upload_kbit,
            download_kbit,
        } = a
        {
            Some((*upload_kbit, *download_kbit))
        } else {
            None
        }
    })
}
/// Management answering for `SETTLE_SECS` in a row within `JUDGE_SECS`:
/// what confirms a profile and, after a rollback, what shows that stock
/// settings work (`radio_guard::Verdict`). The same test for both, so a probe
/// that answers only now and then fails both and strikes nothing.
fn settles(p: &Profile) -> bool {
    let mut healthy = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(guard_model::JUDGE_SECS) {
        if reachable(p) {
            if healthy.get_or_insert_with(Instant::now).elapsed()
                >= Duration::from_secs(guard_model::SETTLE_SECS)
            {
                return true;
            }
        } else {
            healthy = None;
        }
        pause(2);
    }
    false
}
fn confirm(p: &Profile, base: u32) -> io::Result<()> {
    if !settles(p) {
        return Err(fail(NOT_SETTLED));
    }
    sample(p, base)
}
fn sample(p: &Profile, base: u32) -> io::Result<()> {
    let n = count()?;
    // A counter below its baseline: the modem restarted. A fresh baseline,
    // not a failure (the check has already written the cap again).
    let delta = n.checked_sub(base).unwrap_or(0);
    let now = crate::clock::monotonic();
    let prev = json_file("radio-counters")["last_failure_uptime"].as_u64();
    let storm = titan_pd_model::radio::storm(delta, prev, now);
    let last = if delta > 0 { Some(now) } else { prev };
    let sqm = if let Some(r) = rates(p) {
        radio_sqm::reconcile(Some(r))?;
        radio_sqm::stats()?
    } else {
        Value::Null
    };
    atomic(
        &ram("radio-counters"),
        json!({"reconfig_failures":n,"delta":delta,"last_failure_uptime":last,"sqm":sqm})
            .to_string()
            .as_bytes(),
    )?;
    if storm {
        return Err(fail("reconfiguration failure storm"));
    }
    Ok(())
}
fn apply(p: &Profile, old: &Profile) -> io::Result<()> {
    if let Some(why) = recovery_pending() {
        return Err(fail(why));
    }
    let start = Instant::now();
    while !ready() {
        if start.elapsed() > Duration::from_secs(30) {
            return Err(fail("LTE stack unavailable"));
        }
        pause(1);
    }
    if media() == "ATTACHED" && !reachable(p) {
        return Err(fail("management preflight failed"));
    }
    let base = count()?;
    rm(ram("radio-counters"))?;
    let mut journal = p.clone();
    for a in &old.actions {
        if !p.actions.iter().any(|x| discriminant(x) == discriminant(a)) {
            journal.actions.push(a.clone());
        }
    }
    let mut changes = Vec::new();
    for a in &journal.actions {
        let Some(query) = a.query() else {
            continue;
        };
        let reply = console(query)?;
        let prev = old
            .actions
            .iter()
            .find(|x| discriminant(*x) == discriminant(a));
        let stock = !p.actions.contains(a);
        if !prev.unwrap_or(a).matches_reply(&reply, prev.is_none()) {
            return Err(fail("unrecognized modem baseline"));
        }
        if a.matches_reply(&reply, stock) {
            continue;
        }
        changes.push((a, stock));
    }
    if !matches!(media().as_str(), "ATTACHED" | "DETACHED" | "SEARCHING") {
        return Err(fail("unknown attach state"));
    }
    store(&ram("radio-journal"), &journal)?;
    // RAM settings only, and no radio cycle. A cap written while attached
    // takes effect at the next attach; the guard re-checks after it.
    for (a, stock) in &changes {
        set(a, *stock)?;
    }
    if rates(&journal).is_some() {
        if rates(p).is_some() {
            let wait = Instant::now();
            while (!Path::new("/sys/class/net/lte0pdn2").exists() || !crate::revert::mgmt_up())
                && wait.elapsed() < Duration::from_secs(45)
            {
                pause(1);
            }
        }
        radio_sqm::reconcile(rates(p))?;
    }
    confirm(p, base)?;
    for a in p.actions.iter().filter(|a| a.query().is_some()) {
        if !current(a, false)? {
            return Err(fail("profile changed during attach"));
        }
    }
    store(&ram("radio-journal"), p)?;
    Ok(())
}

fn wait_attached(seconds: u64) -> bool {
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        if media() == "ATTACHED" {
            return true;
        }
        pause(2);
    }
    false
}

/// `AT%GLOCKPCELL=0` returns ERROR and changes nothing. Only `1,0,0` clears.
fn clear_pcell() -> io::Result<()> {
    for _ in 0..3 {
        if console(PCELL_CLEAR).is_ok()
            && console(PCELL_QUERY).is_ok_and(|r| model::pcell_state(&r) == Some(None))
        {
            return Ok(());
        }
        pause(2);
    }
    Err(fail("PCell lock not cleared"))
}

/// An attached unit has its radio on. `AT+CFUN?` cannot tell: it reads 1
/// while the radio is off (see `radio_modem::cfun`).
fn radio_on() -> io::Result<()> {
    if media() == "ATTACHED" {
        return Ok(());
    }
    cfun(true)
}

/// The one radio cycle a profile may cause: re-attach so the cap applies,
/// with an optional PCell nudge that is always cleared afterwards.
fn enforce(p: &Profile) -> io::Result<()> {
    let action = p
        .actions
        .iter()
        .find(|a| matches!(a, Action::CarrierAggregation { .. }))
        .ok_or_else(|| fail("no carrier cap"))?;
    let (cap, cycle_hours, nudge) = p.carrier_cap().ok_or_else(|| fail("no carrier cap"))?;
    let hours = cycle_hours.ok_or_else(|| fail("radio cycles are off"))?;
    // Read every condition again right before acting. The guard's
    // over-cap timer is the only value carried in.
    let now = crate::clock::monotonic();
    let before = model::carriers(&nvram::read_value("sqns_connection_sccInfo"));
    let mode_grant = nvram::read_value("cbrs_mode_grant");
    let grant_state = nvram::read_value("cbrs_grant_state");
    let fresh = model::cycle_gate(model::Gate {
        cap,
        cycle_hours,
        carriers: before,
        attached: media() == "ATTACHED",
        over_since: Some(0),
        last_cycle: last_cycle(),
        now,
        mode_grant: &mode_grant,
        grant_state: &grant_state,
        hold: cycle_hold(),
    });
    if let Some(why) = fresh.err().map(str::to_owned).or_else(|| cycle_cap(reboots::SLOTS_AWAY)) {
        eprintln!("radio-worker: enforcement skipped: {why}");
        return Ok(());
    }
    // Count the cycle before acting, so a crash mid-cycle still spends it.
    atomic(&ram("radio-last-cycle"), now.to_string().as_bytes())?;
    record_cycle("enforce")?;
    crate::log(&format!(
        "radio profile: re-attaching once to enforce the {cap}-carrier cap ({} carriers, SAS grant held){}; next no sooner than {hours} h",
        before.unwrap_or(0),
        nudge
            .map(|c: Cell| format!(", PCell nudge EARFCN {} PCI {}", c.earfcn, c.pci))
            .unwrap_or_default()
    ));
    transition(175)?;
    let base = count()?;
    cfun(false)?;
    let mut result = (|| {
        if !current(action, false)? {
            set(action, false)?;
        }
        if let Some(cell) = nudge {
            console(&model::pcell_lock(cell))?;
            if model::pcell_state(&console(PCELL_QUERY)?) != Some(Some(cell)) {
                return Err(fail("PCell nudge read-back failed"));
            }
        }
        Ok(())
    })();
    // The radio always comes back on, even after a failed write.
    let on = cfun(true);
    if result.is_ok() {
        result = on;
    }
    let attached = result.is_ok() && wait_attached(90);
    // The nudge never outlives this cycle, attached or not.
    let cleared = if nudge.is_some() {
        clear_pcell()
    } else {
        Ok(())
    };
    let after = model::carriers(&nvram::read_value("sqns_connection_sccInfo"));
    crate::log(&format!(
        "radio profile: enforcement re-attach {}; carriers now {}{}",
        if attached { "attached" } else { "did not attach within 90 s" },
        after.map_or("unknown".into(), |n| n.to_string()),
        match (&nudge, &cleared) {
            (None, _) => "",
            (Some(_), Ok(())) => "; PCell nudge cleared",
            (Some(_), Err(_)) => "; PCell nudge NOT cleared, reverting",
        }
    ));
    result?;
    cleared?;
    if !attached {
        return Err(fail("no attach after the enforcement re-attach"));
    }
    // A fresh baseline for the reconfiguration-failure check.
    let n = count().unwrap_or(base);
    atomic(
        &ram("radio-counters"),
        json!({"reconfig_failures":n,"delta":0,"last_failure_uptime":null,"sqm":null})
            .to_string()
            .as_bytes(),
    )?;
    rm(ram("radio-transition"))
}
fn restore(p: &Profile) -> io::Result<()> {
    // Restore log routing even if the previous process died inside a query.
    if ram("radio-console-open").exists() {
        console("arm1log 1")?;
    }
    // Stock values in RAM, with no radio cycle. The stock cap takes effect at
    // the next attach. An interrupted enforcement cycle may have left the
    // radio off or the nudge set: turn the radio on and clear the lock.
    let mut ok = true;
    if let Some((_, cycle_hours, nudge)) = p.carrier_cap() {
        if cycle_hours.is_some() {
            ok &= radio_on().is_ok();
        }
        if nudge.is_some() {
            ok &= clear_pcell().is_ok();
        }
    }
    for a in p.actions.iter().filter(|a| a.query().is_some()) {
        ok &= set(a, true).is_ok();
    }
    if p.picker().is_some() {
        ok &= radio_on().is_ok();
        ok &= clear_pcell().is_ok();
        ok &= set(&stock_cap(), true).is_ok();
    }
    if rates(p).is_some() {
        radio_sqm::reconcile(None)?;
    }
    if ok {
        Ok(())
    } else {
        Err(fail("stock restore unconfirmed"))
    }
}

pub fn worker(op: Option<&str>) -> io::Result<()> {
    root()?;
    let p = profile(&ram("radio-target"))?;
    // Every op that drives the modem console holds it from its start, so no
    // flag session slips between a cycle's steps (`console_lock`). A console
    // still busy past the wait is `console_lock::BUSY`: no verdict.
    let _console = match op {
        Some("preflight" | "judge") => None,
        Some(op) if op.starts_with("pick-measure-") => None,
        Some("check") => Some(console_lock::hold(console_lock::CHECK_WAIT)?),
        _ => Some(console_lock::hold(console_lock::RADIO_WAIT)?),
    };
    match op {
        Some("preflight") => preflight(&p),
        Some("judge") => {
            if settles(&p) {
                Ok(())
            } else {
                Err(fail("management does not answer on stock settings either"))
            }
        }
        Some("restore-log") => console("arm1log 1").map(|_| ()),
        Some("rollback") => {
            transition(125)?;
            restore(&profile(&ram("radio-journal"))?)
        }
        Some("apply") => apply(&p, &profile(&ram("radio-active"))?),
        Some("enforce") => enforce(&p),
        Some("pick-back") => pick_back(),
        Some(op) if op.starts_with("pick-cycle-") => pick_cycle(&p, arm_index(op)?),
        Some(op) if op.starts_with("pick-measure-") => pick_measure(&p, arm_index(op)?),
        Some("check") => check(&p),
        _ => Err(fail("invalid worker operation")),
    }
}

/// What a trial needs first: no keeper recovery pending, the LTE stack up,
/// and the unit attached with its management probe answering. Anything else
/// is "not tried": nothing is written or counted.
fn preflight(p: &Profile) -> io::Result<()> {
    if let Some(why) = recovery_pending() {
        return Err(fail(why));
    }
    let start = Instant::now();
    while !ready() {
        if start.elapsed() > Duration::from_secs(30) {
            return Err(fail("LTE stack unavailable"));
        }
        pause(1);
    }
    if media() != "ATTACHED" {
        return Err(fail("not attached"));
    }
    if !reachable(p) {
        pause(3);
        if !reachable(p) {
            return Err(fail("the management probe is not answering"));
        }
    }
    Ok(())
}

/// One check of the running profile, every 30 s.
fn check(p: &Profile) -> io::Result<()> {
    // A detach (tower or SAS outage) is not caused by a profile that never
    // cycles the radio. Judge again after the next attach.
    if media() != "ATTACHED" {
        return Ok(());
    }
    if !reachable(p) {
        pause(3);
        if !reachable(p) {
            return Err(fail(UNREACHABLE));
        }
    }
    // The cap lives in modem RAM. Write it again if something reset it.
    for a in p.actions.iter().filter(|a| a.query().is_some()) {
        if !current(a, false)? {
            set(a, false)?;
            crate::log("radio profile: the carrier cap was reset; written again for the next attach");
        }
    }
    let base = json_file("radio-counters")["reconfig_failures"]
        .as_u64()
        .and_then(|v| v.try_into().ok());
    // A lost baseline (a RAM file) is taken again, not failed.
    match base {
        Some(base) => sample(p, base),
        None => sample(p, count()?),
    }
}

fn stock_cap() -> Action {
    Action::CarrierAggregation {
        carriers: 4,
        cycle_hours: None,
        nudge: None,
    }
}

fn arm_index(op: &str) -> io::Result<usize> {
    op.rsplit('-')
        .next()
        .and_then(|n| n.parse().ok())
        .ok_or_else(|| fail("invalid arm"))
}

/// The minute of the UTC day, for the picker's survey window. The clock is
/// checked with the CPAS window first (`cycle_hold`).
fn minute_utc() -> u16 {
    ((unix_now() % 86_400) / 60) as u16
}

/// The picker's radio cycle onto an arm. Every condition is read again right
/// before acting; one that no longer holds is "not now", and nothing is done.
fn pick_cycle(p: &Profile, i: usize) -> io::Result<()> {
    let picker = p.picker().ok_or_else(|| fail("no carrier picker"))?;
    let arm = *picker.arms.get(i).ok_or_else(|| fail("no such arm"))?;
    if let Some(why) = cycle_hold() {
        return Err(not_now(why));
    }
    if media() != "ATTACHED"
        || nvram::read_value("cbrs_mode_grant") != "1"
        || nvram::read_value("cbrs_grant_state") != "2"
    {
        return Err(not_now("not attached with a held SAS grant"));
    }
    if let Some(why) = cycle_cap(reboots::SLOTS_AWAY) {
        return Err(not_now(&why));
    }
    cycle_to(arm, &format!("on arm {i}"), "pick")
}

/// The way back after a visit no covering grant reached (`PickWatch`): to
/// where the unit was before it, which held its grants then. It has no grant
/// to protect, so only the CPAS window, the clock and the daily cap hold it.
fn pick_back() -> io::Result<()> {
    let back: Arm = serde_json::from_slice(&fs::read(ram("radio-pick-back"))?)
        .map_err(|_| fail("no way back recorded"))?;
    if let Some(why) = cycle_hold() {
        return Err(not_now(why));
    }
    if let Some(why) = cycle_cap(reboots::SLOTS_BACK) {
        return Err(not_now(&why));
    }
    cycle_to(back, "back", "back")
}

/// One picker radio cycle, like the enforcement re-attach, with `arm`'s cap
/// and primary cell. The nudge is cleared at once, attached or not. With no
/// attach within 90 s the radio is on and the nudge gone, so the unit
/// attaches where the tower lets it; the visit's grant wait, and the way
/// back, take it from there.
fn cycle_to(arm: Arm, what: &str, why: &str) -> io::Result<()> {
    let now = monotonic();
    // Counted before acting, so a cycle cut short still counts.
    atomic(&ram("radio-last-cycle"), now.to_string().as_bytes())?;
    record_cycle(why)?;
    crate::log(&format!(
        "carrier picker: re-attaching {what} (EARFCN {} PCI {}, {}-carrier cap)",
        arm.earfcn, arm.pci, arm.carriers
    ));
    transition(175)?;
    let cap = Action::CarrierAggregation {
        carriers: arm.carriers,
        cycle_hours: None,
        nudge: None,
    };
    cfun(false)?;
    let mut result = (|| {
        if !current(&cap, false)? {
            set(&cap, false)?;
        }
        console(&model::pcell_lock(arm.cell()))?;
        if model::pcell_state(&console(PCELL_QUERY)?) != Some(Some(arm.cell())) {
            return Err(fail("PCell nudge read-back failed"));
        }
        Ok(())
    })();
    // The radio always comes back on, and the nudge never outlives the cycle.
    let on = cfun(true);
    if result.is_ok() {
        result = on;
    }
    let attached = result.is_ok() && wait_attached(90);
    let cleared = clear_pcell();
    let landed = carrier_pick_io::attach();
    crate::log(&format!(
        "carrier picker: {}{}",
        match (attached, landed) {
            (true, Some((cell, n))) => format!("attached on EARFCN {} PCI {} with {n} carriers", cell.earfcn, cell.pci),
            (true, None) => "attached".into(),
            (false, _) => "no attach within 90 s".into(),
        },
        if cleared.is_ok() { "; nudge cleared" } else { "; nudge NOT cleared, reverting" }
    ));
    result?;
    cleared?;
    // A fresh baseline for the reconfiguration-failure check.
    if let Ok(n) = count() {
        atomic(
            &ram("radio-counters"),
            json!({"reconfig_failures":n,"delta":0,"last_failure_uptime":null,"sqm":null})
                .to_string()
                .as_bytes(),
        )?;
    }
    rm(ram("radio-transition"))
}

fn pick_measure(p: &Profile, arm: usize) -> io::Result<()> {
    let picker = p.picker().ok_or_else(|| fail("no carrier picker"))?;
    let probe = p.management_probe.ok_or_else(|| fail("no management probe"))?;
    let m = carrier_pick_io::measure(probe, picker.ul_sink.unwrap_or(probe), arm)?;
    atomic(&ram("radio-pick-measure"), &serde_json::to_vec(&m)?)
}

fn load_record(arms: &[pick::Arm]) -> Record {
    fs::read(disk("pick.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<Record>(&b).ok())
        .filter(|r| r.arms == arms)
        .unwrap_or_else(|| Record {
            arms: arms.to_vec(),
            ..Record::default()
        })
}

/// A survey that has not finished in this long is abandoned.
const SURVEY_STALE: u64 = 6 * 3600;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Purpose {
    Survey,
    Hold,
}

/// An arm the picker re-attached to: it waits for covering grants and the
/// settle time before it is measured (survey) or confirmed (hold).
struct Visit {
    arm: usize,
    since: u64,
    granted_at: Option<u64>,
    purpose: Purpose,
    /// Where the unit was before this cycle, which held its grants then: the
    /// way back if no grant covers the arm.
    back: Option<Arm>,
}

struct Survey {
    done: Vec<usize>,
    results: Vec<Measure>,
    started: u64,
    forced: bool,
}

/// The carrier picker in the guard. See `titan_pd_model::carrier_pick`.
#[derive(Default)]
struct PickWatch {
    traffic: Vec<(u64, u64, u64)>,
    record: Option<Record>,
    survey: Option<Survey>,
    visit: Option<Visit>,
    last_hold: Option<u64>,
    shown: String,
    /// A way back the picker owes (`pick_back`). In RAM, so a restarted
    /// guard still goes back.
    back: Option<Arm>,
}

/// A keeper recovery a radio profile must not cross: an IP family change
/// waiting for its confirm (`pd/pending.json`, in its first 10 minutes), or a
/// deaf-watchdog reboot (its strike on flash) in the first hour after boot.
/// Before v1.0.17 either one held every trial for as long as the file stood,
/// which a damaged pending file, or a deaf watchdog turned off, made forever.
fn recovery_pending() -> Option<&'static str> {
    let pd = crate::paths::state_dir();
    let fresh = fs::metadata(pd.join("pending.json"))
        .and_then(|m| m.modified())
        .ok()
        .and_then(|at| at.elapsed().ok())
        .is_some_and(|age| age < Duration::from_secs(600));
    if fresh {
        return Some("an IP family change is waiting for its confirm");
    }
    let strikes = titan_pd_model::deaf::parse_strikes(&read_file(pd.join("watchdog-strikes.txt")));
    (strikes > 0 && monotonic() < 3600).then_some("the deaf watchdog restarted this unit less than an hour ago")
}

/// Why a radio cycle must wait (`radio_guard::cycle_hold`): the CPAS window
/// every keeper reboot waits out, with its margin, or an unset clock.
fn cycle_hold() -> Option<&'static str> {
    guard_model::cycle_hold(crate::run::reboot::cpas_window(), unix_now())
}

/// The radio cycle log (`radio/cycles`), kept like the keeper's reboot log.
fn cycle_log(wall: u64) -> Vec<reboots::Entry> {
    let entries = reboots::parse(&read_file(disk("cycles")));
    reboots::settle(&entries, wall, wall.saturating_sub(monotonic()))
}

/// Why a radio cycle that needs `slots` free ones must wait for the daily cap.
fn cycle_cap(slots: usize) -> Option<String> {
    let wall = unix_now();
    let entries = cycle_log(wall);
    (!guard_model::cycles_allow(&entries, wall, slots)).then(|| {
        format!(
            "{} radio cycles in the last day reach the cap of {}",
            reboots::recent(&entries, wall),
            guard_model::CYCLE_CAP
        )
    })
}

/// Count a radio cycle before it starts.
fn record_cycle(why: &str) -> io::Result<()> {
    let wall = unix_now();
    let entries = cycle_log(wall);
    atomic(&disk("cycles"), reboots::record(&entries, wall, why).as_bytes())
}

/// Whether the picker may cycle the radio now. Read fresh every time.
fn pick_gate(p: &Picker, forced: bool, attached: bool, idle: bool) -> Result<(), String> {
    if let Some(why) = recovery_pending() {
        return Err(why.into());
    }
    pick::cycle_gate(pick::Gate {
        hold: cycle_hold(),
        minute_utc: minute_utc(),
        window: p.window,
        forced,
        attached,
        mode_grant: nvram::read_value("cbrs_mode_grant") == "1",
        grant_state: nvram::read_value("cbrs_grant_state").parse().unwrap_or(0),
        idle,
    })?;
    cycle_cap(reboots::SLOTS_AWAY).map_or(Ok(()), Err)
}

impl PickWatch {
    fn new() -> Self {
        Self {
            back: fs::read(ram("radio-pick-back"))
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok()),
            ..Self::default()
        }
    }

    fn owe_back(&mut self, back: Arm) -> io::Result<()> {
        atomic(&ram("radio-pick-back"), &serde_json::to_vec(&back)?)?;
        self.back = Some(back);
        Ok(())
    }

    fn forget_back(&mut self) -> io::Result<()> {
        self.back = None;
        rm(ram("radio-pick-back"))
    }

    fn tick(&mut self, p: &Picker) -> io::Result<()> {
        let now = crate::clock::monotonic();
        if let Some((rx, tx)) = carrier_pick_io::counters(&carrier_pick_io::customer_dev()) {
            self.traffic.push((now, rx, tx));
        }
        self.traffic.retain(|s| now.saturating_sub(s.0) <= pick::IDLE_SECS + 30);
        let idle = pick::idle(&self.traffic, now);
        let mut record = self.record.take().unwrap_or_else(|| load_record(&p.arms));
        let stepped = self.step(&mut record, p, now, idle);
        self.record = Some(record);
        let (phase, detail) = match &stepped {
            Ok(shown) => shown.clone(),
            Err(e) if no_verdict(e) => ("paused".to_string(), e.to_string()),
            Err(e) => ("failed".to_string(), e.to_string()),
        };
        self.show(&phase, &detail, p)?;
        stepped.map(|_| ())
    }

    fn step(&mut self, record: &mut Record, p: &Picker, now: u64, idle: bool) -> io::Result<(String, String)> {
        let here = carrier_pick_io::attach();
        let current = here.and_then(|(cell, n)| pick::arm_of(&p.arms, cell, n));
        let say = |phase: &str, detail: String| Ok((phase.to_string(), detail));
        // Where a cycle from here comes back to: this arm, or this primary
        // cell with the stock cap.
        let back_here = current.map(|c| p.arms[c]).or_else(|| {
            here.map(|(cell, _)| Arm {
                earfcn: cell.earfcn,
                pci: cell.pci,
                carriers: 4,
            })
        });
        // A visit no grant reached goes back to where the unit held its
        // grants, unless grants cover it where it is by now.
        if let Some(back) = self.back {
            if carrier_pick_io::granted() {
                self.forget_back()?;
                crate::log("carrier picker: grants cover the unit where it is; no way back needed");
            } else {
                if let Some(why) = cycle_hold().map(str::to_owned).or_else(|| cycle_cap(reboots::SLOTS_BACK)) {
                    return say("waiting", format!("back to EARFCN {} PCI {}: {why}", back.earfcn, back.pci));
                }
                run_worker("pick-back", PICK_CYCLE_SECS)?;
                self.forget_back()?;
                self.visit = None;
                self.survey = None;
                // The held arm is tried again no sooner than a hold return.
                self.last_hold = Some(now);
                return say("returned", format!("back on EARFCN {} PCI {}", back.earfcn, back.pci));
            }
        }
        if self.survey.as_ref().is_some_and(|s| now.saturating_sub(s.started) > SURVEY_STALE) {
            self.survey = None;
            if self.visit.as_ref().is_some_and(|v| v.purpose == Purpose::Survey) {
                self.visit = None;
            }
            crate::log("carrier picker: survey abandoned unfinished after 6 hours");
            return say("stopped", "survey abandoned".into());
        }
        // An arm just re-attached to: wait for grants and the settle time.
        if let Some(visit) = self.visit.as_mut() {
            if visit.granted_at.is_none() && carrier_pick_io::granted() {
                visit.granted_at = Some(now);
            }
            match visit.granted_at {
                None if now.saturating_sub(visit.since) > pick::GRANT_WAIT => {
                    let (arm, back) = (visit.arm, visit.back);
                    self.visit = None;
                    self.survey = None;
                    let Some(back) = back else {
                        crate::log(&format!(
                            "carrier picker: no SAS grant covered arm {arm} within {} s; survey stopped",
                            pick::GRANT_WAIT
                        ));
                        return say("stopped", format!("arm {arm}: no covering SAS grant"));
                    };
                    // Before v1.0.17 the unit stayed, and the grant gate kept
                    // it from ever coming back.
                    crate::log(&format!(
                        "carrier picker: no SAS grant covered arm {arm} within {} s; survey stopped; going back to EARFCN {} PCI {}",
                        pick::GRANT_WAIT, back.earfcn, back.pci
                    ));
                    self.owe_back(back)?;
                    return say(
                        "returning",
                        format!("arm {arm}: no covering SAS grant; going back to EARFCN {} PCI {}", back.earfcn, back.pci),
                    );
                }
                None => return say("waiting", format!("arm {}: waiting for SAS grants", visit.arm)),
                Some(t) if now.saturating_sub(t) < pick::SETTLE => {
                    return say("waiting", format!("arm {}: settling", visit.arm));
                }
                Some(_) => {}
            }
            let Some(visit) = self.visit.take() else {
                return say("idle", String::new());
            };
            if visit.purpose == Purpose::Hold {
                if current == Some(visit.arm) {
                    crate::log(&format!("carrier picker: back on held arm {} with covering grants", visit.arm));
                    return say("holding", format!("arm {}", visit.arm));
                }
                crate::log(&format!(
                    "carrier picker: the re-attach for held arm {} landed elsewhere; next try within 6 hours",
                    visit.arm
                ));
                return say("off-arm", format!("re-attach for arm {} landed elsewhere", visit.arm));
            }
            // The burst would crowd the customer: measure only while idle,
            // and again later when the customer interrupts it.
            let arm = visit.arm;
            if !idle || !self.measure(arm) {
                self.visit = Some(visit);
                return say("paused", format!("arm {arm}: waiting for an idle customer"));
            }
            return say("surveying", format!("arm {arm} measured"));
        }
        if let Some(survey) = &self.survey {
            let forced = survey.forced;
            match pick::next_arm(&p.arms, &survey.done, current) {
                Some(i) if Some(i) == current => {
                    if !idle || !carrier_pick_io::granted() {
                        return say("paused", "waiting for an idle customer and covering grants".into());
                    }
                    if !self.measure(i) {
                        return say("paused", format!("arm {i}: customer traffic during the measurement"));
                    }
                    return say("surveying", format!("arm {i} measured in place"));
                }
                Some(i) => {
                    if let Err(why) = pick_gate(p, forced, here.is_some(), idle) {
                        return say("paused", why.into());
                    }
                    run_worker(&format!("pick-cycle-{i}"), PICK_CYCLE_SECS)?;
                    self.visit = Some(Visit {
                        arm: i,
                        since: monotonic(),
                        granted_at: None,
                        purpose: Purpose::Survey,
                        back: back_here,
                    });
                    return say("surveying", format!("arm {i}: re-attached"));
                }
                None => {
                    let Some(survey) = self.survey.take() else {
                        return say("idle", String::new());
                    };
                    let chosen = pick::choose(&p.arms, &survey.results, current, p.ul_weight);
                    *record = Record {
                        arms: p.arms.clone(),
                        chosen,
                        surveyed_at: Some(crate::clock::unix_now()),
                        results: survey.results,
                    };
                    atomic(&disk("pick.json"), &serde_json::to_vec(&*record)?)?;
                    crate::log(&match chosen {
                        Some(c) => format!(
                            "carrier picker: survey done; holding arm {c} (EARFCN {} PCI {}, {}-carrier cap)",
                            p.arms[c].earfcn, p.arms[c].pci, p.arms[c].carriers
                        ),
                        None => "carrier picker: survey done; no arm measured, nothing held".into(),
                    });
                    self.last_hold = None;
                    return say("chosen", chosen.map_or("none".into(), |c| format!("arm {c}")));
                }
            }
        }
        let forced = ram("pick-survey-now").exists();
        let due = forced
            || record.surveyed_at.is_none_or(|t| {
                crate::clock::unix_now().saturating_sub(t) >= u64::from(p.survey_hours) * 3600
            });
        if due {
            match pick_gate(p, forced, here.is_some(), idle) {
                Ok(()) => {
                    rm(ram("pick-survey-now"))?;
                    crate::log(&format!(
                        "carrier picker: survey of {} arms started{}",
                        p.arms.len(),
                        if forced { " (operator request)" } else { "" }
                    ));
                    self.survey = Some(Survey {
                        done: vec![],
                        results: vec![],
                        started: now,
                        forced,
                    });
                    return say("surveying", "started".into());
                }
                Err(why) if forced => return say("waiting", format!("survey requested: {why}")),
                Err(_) => {}
            }
        }
        let Some(c) = record.chosen else {
            return say("idle", "no survey yet".into());
        };
        if current == Some(c) {
            return say("holding", format!("arm {c}"));
        }
        if self.last_hold.is_some_and(|t| now.saturating_sub(t) < pick::HOLD_SPACING) {
            return say("off-arm", format!("left arm {c}; next return within 6 hours"));
        }
        // Going back to the held arm ignores the survey window, nothing else.
        if let Err(why) = pick_gate(p, true, here.is_some(), idle) {
            return say("off-arm", format!("left arm {c}: {why}"));
        }
        self.last_hold = Some(now);
        run_worker(&format!("pick-cycle-{c}"), PICK_CYCLE_SECS)?;
        self.visit = Some(Visit {
            arm: c,
            since: monotonic(),
            granted_at: None,
            purpose: Purpose::Hold,
            back: back_here,
        });
        say("returning", format!("re-attached to arm {c}"))
    }

    /// One visit's measurement. A failed measurement is logged and the arm
    /// counts as visited, so a failed measurement cannot stall a survey.
    /// False when the customer interrupted it: the arm stays to measure again.
    fn measure(&mut self, arm: usize) -> bool {
        let _ = rm(ram("radio-pick-measure"));
        let result = run_worker(&format!("pick-measure-{arm}"), 60).and_then(|()| {
            serde_json::from_slice::<Measure>(&fs::read(ram("radio-pick-measure"))?)
                .map_err(|_| fail("unreadable measurement"))
        });
        if result.as_ref().is_err_and(|e| e.to_string() == pick::CUSTOMER_BUSY) {
            crate::log(&format!("carrier picker: arm {arm}: the customer started traffic; burst stopped, measuring later"));
            return false;
        }
        let Some(survey) = self.survey.as_mut() else {
            return true;
        };
        survey.done.push(arm);
        match result {
            Ok(m) => {
                let sinr: Vec<String> = m.sinr_db.iter().chain(&m.scc_sinr_db).map(i32::to_string).collect();
                crate::log(&format!(
                    "carrier picker: arm {arm} on EARFCN {} PCI {} with {} carriers (SINR {} dB): \
                     {}.{} down estimated, {}.{} up Mbps, {} ms",
                    m.pcell.earfcn,
                    m.pcell.pci,
                    m.carriers,
                    sinr.join("/"),
                    m.dl_kbps / 1000,
                    m.dl_kbps % 1000 / 100,
                    m.ul_kbps / 1000,
                    m.ul_kbps % 1000 / 100,
                    m.rtt_ms.map_or("?".into(), |r| r.to_string())
                ));
                survey.results.push(m);
            }
            Err(e) => crate::log(&format!("carrier picker: arm {arm} not measured: {e}")),
        }
        true
    }

    fn show(&mut self, phase: &str, detail: &str, p: &Picker) -> io::Result<()> {
        let record = self.record.as_ref();
        let results: Vec<Value> = record
            .map(|r| {
                r.results
                    .iter()
                    .map(|m| {
                        json!({"arm":m.arm,"earfcn":m.pcell.earfcn,"pci":m.pcell.pci,"carriers":m.carriers,
                            "ul_scc":m.ul_scc,"sinr_db":m.sinr_db,"scc_sinr_db":m.scc_sinr_db,"rsrp_dbm":m.rsrp_dbm,
                            "down_estimate_kbps":m.dl_kbps,"up_kbps":m.ul_kbps,"rtt_ms":m.rtt_ms,
                            "modem_max_down_kbps":m.dl_max_kbps,"modem_max_up_kbps":m.ul_max_kbps,
                            "score":pick::score(m, p.ul_weight),"held":m.held(&p.arms)})
                    })
                    .collect()
            })
            .unwrap_or_default();
        let text = json!({
            "phase":phase,
            "detail":detail,
            "chosen":record.and_then(|r| r.chosen),
            "surveyed_at":record.and_then(|r| r.surveyed_at),
            "survey_visited":self.survey.as_ref().map(|s| s.done.clone()),
            "results":results,
        })
        .to_string();
        if text != self.shown {
            atomic(&ram("radio-pick"), text.as_bytes())?;
            self.shown = text;
        }
        Ok(())
    }
}
