//! Operator JSON interface and the supervisor for volatile radio settings.
//! Only the guard starts mutation workers. Its monotonic deadline covers the
//! whole worker process group, including vendor programs that stop responding.
//!
//! Applying or removing a profile never cycles the radio. A carrier cap
//! written while attached waits for the next attach. The only radio cycle is
//! the opt-in enforcement re-attach, gated by `titan_pd_model::radio::cycle_gate`.
use crate::{
    radio_modem::{cfun, console},
    radio_sqm,
};
use serde_json::{Value, json};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    mem::discriminant,
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Condvar, Mutex, OnceLock},
    thread,
    time::{Duration, Instant},
};
use titan_pd_model::{
    config::persistent_volume_mounted,
    radio::{self as model, Action, Cell, PCELL_CLEAR, PCELL_QUERY, Profile, failures},
};

/// Seconds between health and carrier checks while a profile is active.
const CHECK_EVERY: u64 = 30;
/// After an attach, re-check the carrier state this soon.
const AFTER_ATTACH: u64 = 20;
/// Fallback poll period when no radio profile is configured.
const IDLE_SUPERVISE_SECS: u64 = 60;

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
const RAM: &str = "/tmp/titan-pd-keeper";
fn disk(name: &str) -> PathBuf {
    Path::new(DISK).join(name)
}
fn ram(name: &str) -> PathBuf {
    Path::new(RAM).join(name)
}
fn fail(s: &str) -> io::Error {
    io::Error::other(s.to_owned())
}
fn pause(n: u64) {
    thread::sleep(Duration::from_secs(n));
}

fn atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    if path.starts_with(DISK) {
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
fn strikes() -> io::Result<u8> {
    match fs::read_to_string(disk("strikes")) {
        Ok(v) => v.trim().parse().map_err(|_| fail("invalid boot guard")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
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
pub fn supervise() {
    if !persistent_volume_mounted() {
        return;
    }
    thread::spawn(|| {
        if let Err(e) = listen() {
            eprintln!("radio profile API: {e}");
        }
    });
    thread::spawn(|| {
        let mut seen = 0u64;
        loop {
            // No profile on a stock installation. Only inspect the filesystem.
            let active = disk("profile.json").exists() || ram("radio-journal").exists();
            if active {
                let _ = Command::new("/tmp/titan-pd-keeper/titan-pd-keeper")
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
    if unsafe { libc::geteuid() } != 0 {
        return Err(fail("operator access required"));
    }
    if !persistent_volume_mounted() {
        return Err(fail("persistent volume unavailable"));
    }
    Ok(())
}

fn private_runtime() -> io::Result<()> {
    let md = fs::symlink_metadata(RAM)?;
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
            fs::create_dir_all(DISK)?;
            store(&disk("profile.json"), &p)?;
            wake_supervisor();
            Ok(json!({"accepted":true}))
        }
        Some("status") => {
            let mut guard = json_file("radio-status");
            if guard.is_null() {
                guard = json!({"phase":"off","detail":"no trial this boot"});
            }
            Ok(json!({
                "guard":guard,
                "strikes":strikes().ok(),
                "counters":json_file("radio-counters"),
                "carriers":json_file("radio-carriers"),
            }))
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
        Some("get" | "status") => json!({"op":op}),
        Some("set") => {
            let mut bytes = vec![];
            io::stdin().take(4097).read_to_end(&mut bytes)?;
            let p = Profile::parse(&bytes).map_err(fail)?;
            json!({"op":"set","profile":p})
        }
        _ => return Err(fail("usage: radio-profile get|set|status")),
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
    let mut cmd = Command::new("/tmp/titan-pd-keeper/titan-pd-keeper");
    cmd.args(["radio-worker", op])
        .stdin(Stdio::null())
        .process_group(0);
    let ppid = std::process::id();
    unsafe {
        cmd.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != ppid as i32
            {
                return Err(fail("guard gone"));
            }
            Ok(())
        });
    }
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
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
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
    let until = crate::run::monotonic() + seconds;
    atomic(&ram("radio-transition"), until.to_string().as_bytes())
}

fn rollback() -> io::Result<()> {
    if ram("radio-console-open").exists() && !ram("radio-journal").exists() {
        run_worker("restore-log", 15)?;
    }
    if ram("radio-journal").exists() {
        transition(125)?;
        status("reverting", "restoring stock settings")?;
        if run_worker("rollback", 120).is_err() {
            // A cold start restores all modem RAM and kernel qdiscs. Disarm
            // the saved profile durably before requesting that last resort.
            atomic(&disk("strikes"), b"3")?;
            store(&disk("profile.json"), &Profile::default())?;
            status(
                "recovery",
                "stock restore failed; restarting with profile off",
            )?;
            if !Command::new("reboot").status()?.success() {
                return Err(fail("restart failed"));
            }
            pause(120);
            return Err(fail("stock restart still pending"));
        }
        rm(ram("radio-journal"))?;
    }
    rm(ram("radio-active"))?;
    rm(ram("radio-transition"))
}

fn lock_guard() -> io::Result<File> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(ram("radio.lock"))?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(fail("guard already running"));
    }
    Ok(file)
}

pub fn guard() -> io::Result<()> {
    root()?;
    private_runtime()?;
    let _lock = lock_guard()?;
    // A guard restart on this boot inherits the RAM journal. A power cycle
    // clears the modem and the journal together, but preserves its strike.
    if ram("radio-journal").exists() {
        store(&ram("radio-blocked"), &profile(&ram("radio-target"))?)?;
        rollback()?;
        status("reverted", "interrupted profile")?;
    }
    let mut watch = CarrierWatch::default();
    loop {
        if ram("stopped").exists() {
            rollback()?;
            return Ok(());
        }
        let desired = profile(&disk("profile.json"));
        let active = profile(&ram("radio-active"))?;
        let desired = match desired {
            Ok(p) => p,
            Err(_) => {
                rollback()?;
                status("blocked", "invalid saved profile")?;
                pause(10);
                continue;
            }
        };
        if desired.actions.is_empty() {
            rollback()?;
            rm(ram("radio-blocked"))?;
            if strikes().unwrap_or(3) != 0 {
                atomic(&disk("strikes"), b"0")?;
            }
            if json_file("radio-status")["phase"] != "off" {
                status("off", "stock")?;
            }
            pause(5);
            continue;
        }
        if desired != active {
            let Ok(n) = strikes() else {
                rollback()?;
                status("locked", "invalid strike record; save Off to reset")?;
                pause(5);
                continue;
            };
            if n >= 3 || profile(&ram("radio-blocked"))? == desired {
                rollback()?;
                if n >= 3 {
                    status("locked", "three unsuccessful trials")?;
                }
                pause(5);
                continue;
            }
            fs::create_dir_all(DISK)?;
            store(&ram("radio-target"), &desired)?;
            atomic(&disk("strikes"), (n + 1).to_string().as_bytes())?;
            store(&ram("radio-blocked"), &desired)?;
            status("applying", "waiting for profile confirmation")?;
            match run_worker("apply", 180) {
                Ok(()) => {
                    store(&ram("radio-active"), &desired)?;
                    atomic(&disk("strikes"), b"0")?;
                    rm(ram("radio-blocked"))?;
                    status("active", "confirmed")?;
                    watch = CarrierWatch::default();
                }
                Err(e) => {
                    store(&ram("radio-blocked"), &desired)?;
                    rollback()?;
                    status("reverted", &e.to_string())?;
                }
            }
        } else if watch.due(crate::run::monotonic(), media() == "ATTACHED") {
            let checked = run_worker("check", 35)
                .and_then(|()| watch.carriers(&desired, crate::run::monotonic()));
            if let Err(e) = checked {
                atomic(&disk("strikes"), b"1")?;
                store(&ram("radio-blocked"), &desired)?;
                rollback()?;
                status("reverted", &e.to_string())?;
            }
        }
        pause(5);
    }
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
        let carriers = model::carriers(&nvram_field(b"sqns_connection_sccInfo="));
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
        let mode_grant = nvram_field(b"cbrs_mode_grant=");
        let grant_state = nvram_field(b"cbrs_grant_state=");
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
        });
        atomic(
            &ram("radio-carriers"),
            json!({
                "cap":cap,
                "carriers":carriers,
                "over_cap_seconds":self.over_since.map(|t| now.saturating_sub(t)),
                "last_cycle_uptime":last_cycle,
                "enforcement":verdict.err().unwrap_or("due"),
            })
            .to_string()
            .as_bytes(),
        )?;
        if verdict.is_ok() {
            status("enforcing", "re-attaching once to enforce the carrier cap")?;
            run_worker("enforce", 170)?;
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

fn nvram_field(key: &[u8]) -> String {
    let raw = fs::read("/tmp/nvram.cfg").unwrap_or_default();
    let value = |name: &[u8]| {
        raw.split(|b| *b == 0 || *b == b'\n')
            .find_map(|s| s.strip_prefix(name))
            .map(|s| String::from_utf8_lossy(s).trim().to_string())
            .unwrap_or_default()
    };
    value(key)
}
fn media() -> String {
    nvram_field(b"sqns_connection_mediaState=")
}
fn ready() -> bool {
    nvram_field(b"sqns_identity_boardName=") == "GDM7243AP-ODU-E-B48"
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
        && crate::mgmt_up()
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
    failures(&console("rrc dm reest stat ?")?).ok_or_else(|| fail("missing RRC counter"))
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
fn confirm(p: &Profile, base: u32) -> io::Result<()> {
    let mut healthy = None;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(90) {
        if reachable(p) {
            if healthy.get_or_insert_with(Instant::now).elapsed() >= Duration::from_secs(30) {
                return sample(p, base);
            }
        } else {
            healthy = None;
        }
        pause(2);
    }
    Err(fail("management failed to settle"))
}
fn sample(p: &Profile, base: u32) -> io::Result<()> {
    let n = count()?;
    let delta = n
        .checked_sub(base)
        .ok_or_else(|| fail("modem counters reset"))?;
    let now = crate::run::monotonic();
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
    let pd = crate::state();
    let strikes = fs::read_to_string(pd.join("watchdog-strikes.txt")).unwrap_or_default();
    if pd.join("pending.json").exists() || titan_pd_model::deaf::parse_strikes(&strikes) > 0 {
        return Err(fail("keeper recovery already pending"));
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
            while (!Path::new("/sys/class/net/lte0pdn2").exists() || !crate::mgmt_up())
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

fn radio_on() -> io::Result<()> {
    if console("AT+CFUN?")?.lines().any(|s| s.trim() == "+CFUN: 1") {
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
    let now = crate::run::monotonic();
    let before = model::carriers(&nvram_field(b"sqns_connection_sccInfo="));
    let mode_grant = nvram_field(b"cbrs_mode_grant=");
    let grant_state = nvram_field(b"cbrs_grant_state=");
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
    });
    if let Err(why) = fresh {
        eprintln!("radio-worker: enforcement skipped: {why}");
        return Ok(());
    }
    // Count the cycle before acting, so a crash mid-cycle still spends it.
    atomic(&ram("radio-last-cycle"), now.to_string().as_bytes())?;
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
    let after = model::carriers(&nvram_field(b"sqns_connection_sccInfo="));
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
    match op {
        Some("restore-log") => console("arm1log 1").map(|_| ()),
        Some("rollback") => restore(&profile(&ram("radio-journal"))?),
        Some("apply") => apply(&p, &profile(&ram("radio-active"))?),
        Some("enforce") => enforce(&p),
        Some("check") => {
            // A detach (tower or SAS outage) is not caused by a profile that
            // never cycles the radio. Judge again after the next attach.
            if media() != "ATTACHED" {
                return Ok(());
            }
            if !reachable(&p) {
                pause(3);
                if !reachable(&p) {
                    return Err(fail("management unreachable"));
                }
            }
            // The cap lives in modem RAM. Write it again if something reset it.
            for a in p.actions.iter().filter(|a| a.query().is_some()) {
                if !current(a, false)? {
                    set(a, false)?;
                    crate::log("radio profile: the carrier cap was reset; written again for the next attach");
                }
            }
            let counters = json_file("radio-counters");
            let base = counters["reconfig_failures"]
                .as_u64()
                .and_then(|v| v.try_into().ok())
                .ok_or_else(|| fail("counter baseline unavailable"))?;
            sample(&p, base)
        }
        _ => Err(fail("invalid worker operation")),
    }
}
