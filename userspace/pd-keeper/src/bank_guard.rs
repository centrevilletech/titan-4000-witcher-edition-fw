//! The bank guard on the unit: the reads, the checks, the one NV write and
//! the reboot. Every decision is in `titan_pd_model::bank_guard`. See
//! `docs/bank-guard.md`.
//!
//! `titan-pd-keeper bank-guard boot` runs once per boot, started by
//! `/etc/init.d/witcher-bank-guard`, as its own process: one of the things it
//! judges is whether the keeper itself stays up.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::json;
use titan_pd_model::bank_guard::{
    self as model, ArmRecord, Boot, Confirm, Marker, Plan, Round, Settings, State, Table, UbiTally,
    Verdict,
};
use titan_pd_model::{config, deaf};

use crate::{log, log_ram};

const MGMT_DEV: &str = "lte0pdn0";
/// The helper's own alarm is 30 s.
const HELPER_TIMEOUT: Duration = Duration::from_secs(40);
const REBOOT_FORCE_AFTER: u64 = 45;
const REBOOT_GIVE_UP_AFTER: u64 = 120;
const CMN_SIZE: u64 = 0x10_0000;
/// `MEMGETBADBLOCK`, `_IOW('M', 11, __kernel_loff_t)`, on ARM and x86.
const MEMGETBADBLOCK: u32 = 0x4008_4d0b;

pub fn main(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("boot") if args.len() == 1 => boot(),
        Some("status") if args.len() == 1 => status(),
        Some("preflight") if args.len() == 1 => preflight(),
        Some("arm") if args.len() == 1 => arm(),
        _ => {
            eprintln!("usage: titan-pd-keeper bank-guard boot|status|preflight|arm");
            64
        }
    }
}

fn env_path(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

fn read_text(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// `/mnt/titan-api/bank-guard`, only while the persistent volume is mounted.
fn guard_dir() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("TITAN_BANK_GUARD_DIR") {
        return Some(PathBuf::from(path));
    }
    config::persistent_volume_mounted().then(|| PathBuf::from("/mnt/titan-api/bank-guard"))
}

fn boot_id() -> String {
    read_text(&env_path("TITAN_BOOT_ID", "/proc/sys/kernel/random/boot_id"))
        .trim()
        .to_owned()
}

fn running() -> Result<usize, String> {
    model::running_bank(&read_text(&env_path("TITAN_CMDLINE", "/proc/cmdline")))
}

fn proc_mtd() -> String {
    read_text(&env_path("TITAN_PROC_MTD", "/proc/mtd"))
}

/// Uptime, real or (for tests) virtual: `TITAN_BANK_GUARD_VIRTUAL_CLOCK` sets a
/// start time and every wait advances it instead of sleeping.
struct Clock {
    virtual_now: Option<u64>,
}

impl Clock {
    fn new() -> Self {
        Self {
            virtual_now: std::env::var("TITAN_BANK_GUARD_VIRTUAL_CLOCK")
                .ok()
                .and_then(|v| v.trim().parse().ok()),
        }
    }

    fn uptime(&self) -> u64 {
        self.virtual_now.unwrap_or_else(|| {
            read_text(&env_path("TITAN_UPTIME", "/proc/uptime"))
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<f64>().ok())
                .unwrap_or(0.0) as u64
        })
    }

    fn sleep(&mut self, secs: u64) {
        match self.virtual_now.as_mut() {
            Some(now) => *now += secs,
            None => thread::sleep(Duration::from_secs(secs)),
        }
    }
}

/// One NAND partition, read through the MTD character device. Tests point
/// `TITAN_MTD_DIR` at regular files, which have no bad blocks.
struct Mtd {
    file: File,
    regular: bool,
    capacity: u64,
}

impl Mtd {
    fn open(number: usize, capacity: u64) -> Result<Self, String> {
        let test = std::env::var_os("TITAN_MTD_DIR").is_some();
        let path = env_path("TITAN_MTD_DIR", "/dev").join(format!("mtd{number}"));
        let file = File::open(&path).map_err(|e| format!("cannot open mtd{number}: {e}"))?;
        let kind = file
            .metadata()
            .map_err(|e| format!("cannot inspect mtd{number}: {e}"))?;
        let regular = kind.file_type().is_file();
        if !(kind.file_type().is_char_device() || (regular && test)) {
            return Err(format!("mtd{number} is not a flash device"));
        }
        let capacity = if regular { kind.len().min(capacity) } else { capacity };
        Ok(Self {
            file,
            regular,
            capacity,
        })
    }

    fn blocks(&self) -> u64 {
        self.capacity / model::ERASE as u64
    }

    fn bad(&self, offset: u64) -> Result<bool, String> {
        if self.regular {
            return Ok(false);
        }
        let mut location = offset as i64;
        // SAFETY: MEMGETBADBLOCK reads one loff_t through the pointer.
        let result = unsafe {
            libc::ioctl(self.file.as_raw_fd(), MEMGETBADBLOCK as _, &mut location)
        };
        if result < 0 {
            Err(format!(
                "cannot ask the NAND driver about bad blocks: {}",
                io::Error::last_os_error()
            ))
        } else {
            Ok(result != 0)
        }
    }

    fn read_at(&mut self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
        let mut buffer = vec![0u8; length];
        self.file
            .seek(SeekFrom::Start(offset))
            .map_err(|e| format!("NAND seek failed: {e}"))?;
        self.file
            .read_exact(&mut buffer)
            .map_err(|e| format!("NAND read failed: {e}"))?;
        Ok(buffer)
    }

    /// `size` bytes as the vendor writer laid them down: bad blocks skipped.
    fn read_logical(&mut self, size: u64, mut sink: impl FnMut(&[u8])) -> Result<(), String> {
        let mut left = size;
        let mut block = 0u64;
        while left > 0 {
            if block >= self.blocks() {
                return Err("the image runs past the usable NAND".into());
            }
            let offset = block * model::ERASE as u64;
            block += 1;
            if self.bad(offset)? {
                continue;
            }
            let take = left.min(model::ERASE as u64) as usize;
            sink(&self.read_at(offset, take)?);
            left -= take as u64;
        }
        Ok(())
    }
}

/// The bank table as the kernel reads it at boot, straight from `cmnnv`.
struct RawView {
    table: Table,
    copy: usize,
    blocks: [usize; 2],
    seqs: [Result<u32, String>; 2],
}

fn raw_view() -> Result<RawView, String> {
    model::mtd_layout_ok(&proc_mtd())?;
    let mut mtd = Mtd::open(8, CMN_SIZE)?;
    let bad = (0..mtd.blocks())
        .map(|block| mtd.bad(block * model::ERASE as u64))
        .collect::<Result<Vec<_>, _>>()?;
    let blocks = model::cmn_copy_blocks(&bad).ok_or("cmnnv has fewer than three good blocks")?;
    let first = mtd.read_at(blocks[0] as u64 * model::ERASE as u64, model::ERASE)?;
    let second = mtd.read_at(blocks[1] as u64 * model::ERASE as u64, model::ERASE)?;
    let (copy, table) = model::cmn_select([Some(first.as_slice()), Some(second.as_slice())])?;
    Ok(RawView {
        table,
        copy,
        blocks,
        seqs: [model::cmn_copy(&first), model::cmn_copy(&second)],
    })
}

fn raw_table() -> Result<Table, String> {
    raw_view().map(|view| view.table)
}

fn helper() -> PathBuf {
    env_path("TITAN_NV23_HELPER", "/usr/lib/titan-api/witcher-nv23")
}

/// Run `witcher-nv23`; its exit code and output.
fn run_helper(arg: &str, input: Option<&[u8]>) -> Result<(i32, Vec<u8>), String> {
    let mut child = Command::new(helper())
        .arg(arg)
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start witcher-nv23: {e}"))?;
    if let (Some(bytes), Some(mut stdin)) = (input, child.stdin.take()) {
        let written = stdin.write_all(bytes);
        drop(stdin);
        if let Err(e) = written {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("cannot hand the table to witcher-nv23: {e}"));
        }
    }
    let mut output = Vec::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_end(&mut output);
    }
    let deadline = Instant::now() + HELPER_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok((status.code().unwrap_or(-1), output)),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("witcher-nv23 did not finish".into());
            }
        }
    }
}

/// The vendor library's view, which is its RAM copy.
fn vendor_table() -> Result<Table, String> {
    match run_helper("read", None)? {
        (0, output) => Table::from_bytes(&output),
        (code, _) => Err(format!("witcher-nv23 read failed (exit {code})")),
    }
}

/// The table only when the vendor's RAM copy and the raw flash agree. One
/// retry, in case a vendor write was in flight.
fn agreed_table() -> Result<Table, String> {
    let mut last = String::new();
    for attempt in 0..2 {
        if attempt > 0 {
            thread::sleep(Duration::from_secs(1));
        }
        match (vendor_table(), raw_table()) {
            (Ok(vendor), Ok(raw)) if vendor == raw => return Ok(vendor),
            (Ok(_), Ok(_)) => {
                last = "the vendor library and the raw cmnnv flash show different bank tables".into()
            }
            (Err(e), _) => last = format!("vendor read: {e}"),
            (_, Err(e)) => last = format!("raw flash read: {e}"),
        }
    }
    Err(last)
}

/// The old bank's own checks: kernel and modem firmware byte-exact against
/// their record checksums, the root filesystem's UBI structure.
fn check_bank(table: &Table, bank: usize) -> Result<(), String> {
    model::mtd_layout_ok(&proc_mtd())?;
    for part in [0usize, 2] {
        let record = table.record(part, bank);
        let name = model::PARTITIONS[part][bank];
        let mut mtd = Mtd::open(model::mtd_number(part, bank), u64::from(model::LIMITS[part]))?;
        let mut adler = model::Adler::default();
        let mut head = Vec::with_capacity(64);
        mtd.read_logical(u64::from(record.size), |chunk| {
            let want = 64usize.saturating_sub(head.len()).min(chunk.len());
            head.extend_from_slice(&chunk[..want]);
            adler.update(chunk);
        })
        .map_err(|e| format!("{name}: {e}"))?;
        if adler.finish() != record.adler {
            return Err(format!("{name}: the flash does not match its record checksum"));
        }
        let header = if part == 0 {
            model::kernel_header_ok(&head, record.size)
        } else {
            model::modem_header_ok(&head)
        };
        header.map_err(|e| format!("{name}: {e}"))?;
    }
    let name = model::PARTITIONS[1][bank];
    let mut mtd = Mtd::open(model::mtd_number(1, bank), u64::from(model::LIMITS[1]))?;
    let mut tally = UbiTally::default();
    for block in 0..mtd.blocks() {
        let offset = block * model::ERASE as u64;
        if mtd.bad(offset)? {
            continue;
        }
        let ec = mtd.read_at(offset, 64)?;
        match model::ubi_ec(&ec) {
            Ok(Some((vid_at, data_at))) => {
                let vid = mtd.read_at(offset + vid_at as u64, 64)?;
                let data = match model::ubi_vid(&vid) {
                    Ok(Some(_)) => Some(mtd.read_at(offset + data_at as u64, 172)?),
                    _ => None,
                };
                tally.add(block as usize, &ec, Some(vid.as_slice()), data.as_deref());
            }
            _ => tally.add(block as usize, &ec, None, None),
        }
    }
    tally.verdict().map_err(|e| format!("{name}: {e}"))
}

fn sys_net() -> PathBuf {
    env_path("TITAN_SYS_NET", "/sys/class/net")
}

fn carrier(dev: &str) -> bool {
    read_text(&sys_net().join(dev).join("carrier")).trim() == "1"
}

fn addresses(dev: &str) -> String {
    Command::new(std::env::var("TITAN_IP").unwrap_or_else(|_| "ip".into()))
        .args(["addr", "show", "dev", dev])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default()
}

/// The management bearer has carrier and an IPv4 or global IPv6 address.
fn mgmt_up() -> bool {
    carrier(MGMT_DEV)
        && addresses(MGMT_DEV)
            .lines()
            .map(str::trim)
            .any(|line| line.starts_with("inet ") || (line.starts_with("inet6 ") && line.contains("scope global")))
}

/// The lowest customer bearer (`lte0pdn1` and up) with carrier.
fn customer_bearer() -> Option<String> {
    let mut names: Vec<String> = fs::read_dir(sys_net())
        .ok()?
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| {
            name.strip_prefix("lte0pdn")
                .is_some_and(|n| !n.is_empty() && n != "0" && n.bytes().all(|b| b.is_ascii_digit()))
        })
        .filter(|name| carrier(name))
        .collect();
    names.sort();
    names.into_iter().next()
}

fn customer_ok(settings: &Settings) -> bool {
    if !settings.require_customer {
        return true;
    }
    let Some(dev) = customer_bearer() else {
        return false;
    };
    settings.customer_targets.is_empty() || ping_round(&settings.customer_targets, Some(dev.as_str())) == Some(true)
}

/// One ping to each target at once. `None` when there is nothing to ask.
fn ping_round(targets: &[IpAddr], dev: Option<&str>) -> Option<bool> {
    let mut children: Vec<Child> = targets
        .iter()
        .filter_map(|target| {
            let program = if target.is_ipv6() { "ping6" } else { "ping" };
            let mut command = Command::new(std::env::var("TITAN_PING").unwrap_or_else(|_| program.into()));
            command.args(["-c", "1", "-W", "4"]);
            if let Some(dev) = dev {
                command.args(["-I", dev]);
            }
            command
                .arg(target.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()
        })
        .collect();
    if children.is_empty() {
        return None;
    }
    let started = Instant::now();
    let mut heard = false;
    loop {
        let mut running = false;
        for child in children.iter_mut() {
            match child.try_wait() {
                Ok(Some(status)) => heard |= status.success(),
                Ok(None) => running = true,
                Err(_) => {}
            }
        }
        if heard || !running || started.elapsed() >= Duration::from_secs(model::PROBE_TIMEOUT) {
            break;
        }
        thread::sleep(Duration::from_millis(200));
    }
    for child in children.iter_mut() {
        let _ = child.kill();
        let _ = child.wait();
    }
    Some(heard)
}

/// The guard's own targets, else the deaf watchdog's.
fn targets(settings: &Settings) -> Vec<IpAddr> {
    if !settings.targets.is_empty() {
        return settings.targets.clone();
    }
    let watchdog = deaf::parse_settings(&read_text(&crate::state().join("watchdog.conf")));
    let dns = if watchdog.targets.is_empty() {
        Command::new("nvram_get")
            .args(["0", "wan_get_dns"])
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    deaf::targets(&watchdog, &dns)
}

/// The keeper process the supervisor started, if it started in this boot.
fn keeper_pid(boot_id: &str) -> Option<u32> {
    let runtime = crate::runtime();
    if boot_id.is_empty() || read_text(&runtime.join("boot-id")).trim() != boot_id {
        return None;
    }
    let pid: u32 = read_text(&runtime.join("keeper.pid"))
        .trim()
        .parse()
        .ok()
        .filter(|pid| *pid > 1)?;
    let cmdline = fs::read(env_path("TITAN_PROC", "/proc").join(pid.to_string()).join("cmdline")).ok()?;
    let mut args = cmdline.split(|&b| b == 0);
    let program = args.next()?;
    (program.ends_with(b"titan-pd-keeper") && args.next() == Some(b"run".as_slice())).then_some(pid)
}

/// Write through a synced temporary file, then sync the directory, so a power
/// cut leaves the old file or the new one.
fn write_atomic(path: &Path, bytes: &[u8]) -> bool {
    let temp = path.with_extension("tmp");
    let written = (|| -> io::Result<()> {
        let mut file = File::create(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    written.is_ok() && fs::read(path).is_ok_and(|back| back == bytes)
}

enum Loaded {
    Fresh,
    Ready(State),
    Damaged(String),
}

fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

fn load_state(dir: &Path) -> Loaded {
    match fs::read_to_string(state_path(dir)) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Loaded::Fresh,
        Err(e) => Loaded::Damaged(e.to_string()),
        Ok(text) => match serde_json::from_str::<State>(&text) {
            Ok(state) => Loaded::Ready(state),
            Err(e) => Loaded::Damaged(e.to_string()),
        },
    }
}

/// The boot and switch counters bound the guard, so a write that does not
/// read back counts as not written.
fn store_state(dir: &Path, state: &State) -> bool {
    let Ok(text) = serde_json::to_string_pretty(state) else {
        return false;
    };
    let _ = fs::create_dir_all(dir);
    write_atomic(&state_path(dir), text.as_bytes())
        && matches!(load_state(dir), Loaded::Ready(back) if back == *state)
}

fn collect_markers(dir: &Path, boot_id: &str, running: usize) -> Vec<Marker> {
    let mut markers = Vec::new();
    let operation = env_path("TITAN_FIRMWARE_OPERATION", "/mnt/titan-api/firmware-operation.json");
    markers.extend(model::titan_api_marker(&read_text(&operation)));
    if let Ok(record) = serde_json::from_str::<ArmRecord>(&read_text(&dir.join("arm.json"))) {
        markers.extend(model::arm_marker(&record, boot_id));
    }
    markers.extend(model::first_boot_marker(
        &read_text(&dir.join("volume-created")),
        boot_id,
        running,
    ));
    markers
}

fn boot() -> i32 {
    let Some(dir) = guard_dir() else {
        eprintln!("bank guard: the persistent volume is not mounted; nothing to do");
        return 0;
    };
    let _ = fs::create_dir_all(&dir);
    let settings = model::parse_settings(&read_text(&dir.join("config")));
    if !settings.enabled {
        log_ram("bank guard: off (enabled=0 in its config)");
        return 0;
    }
    let boot_id = boot_id();
    let running = match running() {
        Ok(bank) => bank,
        Err(e) => {
            log(&format!("bank guard: {e}; off this boot"));
            return 0;
        }
    };
    let table = agreed_table();
    if let Err(e) = &table {
        log(&format!("bank guard: cannot read the bank table both ways: {e}"));
    }
    let markers = collect_markers(&dir, &boot_id, running);
    let mut state = match load_state(&dir) {
        Loaded::Fresh => State::default(),
        Loaded::Ready(state) => state,
        Loaded::Damaged(e) => {
            // Without its counters the guard could loop. Start over with every
            // marker on disk already used, and act on nothing this boot.
            let _ = fs::rename(state_path(&dir), dir.join("state.json.bad"));
            let mut fresh = State::default();
            for marker in &markers {
                fresh.consumed.push(marker.fingerprint.clone());
            }
            let stored = store_state(&dir, &fresh);
            log(&format!(
                "bank guard: its state file was unreadable ({e}); kept as state.json.bad, started over without arming (saved: {stored})"
            ));
            return 0;
        }
    };
    let before = state.clone();
    let (plan, notes) = model::on_boot(
        &mut state,
        &Boot {
            running,
            table: table.as_ref().ok(),
            markers: &markers,
        },
    );
    for note in &notes {
        log(note);
    }
    if state != before && !store_state(&dir, &state) {
        log("bank guard: cannot record this boot in its state file; not acting this boot");
        return 0;
    }
    let Ok(table) = table else {
        return 0;
    };
    let mut clock = Clock::new();
    match plan {
        Plan::Stop(_) => 0,
        Plan::Idle => watch(&dir, &settings, state, &table, running, &boot_id, false, &mut clock),
        Plan::Watch => watch(&dir, &settings, state, &table, running, &boot_id, true, &mut clock),
        Plan::SwitchNow(why) => switch_back(&dir, state, &table, &why, &mut clock),
    }
}

fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[allow(clippy::too_many_arguments)]
fn watch(
    dir: &Path,
    settings: &Settings,
    mut state: State,
    table: &Table,
    running: usize,
    boot_id: &str,
    armed: bool,
    clock: &mut Clock,
) -> i32 {
    let targets = targets(settings);
    let mut confirm = Confirm::new(settings.confirm_secs);
    if armed {
        log(&format!(
            "bank guard: proof needed within {} s of boot: a management address, an answer from {} target(s) through the core, a steady keeper{}",
            settings.confirm_secs,
            targets.len(),
            if settings.require_customer { ", the customer bearer" } else { "" }
        ));
    }
    loop {
        let round = Round {
            uptime: clock.uptime(),
            mgmt_up: mgmt_up(),
            heard: ping_round(&targets, None),
            keeper_pid: keeper_pid(boot_id),
            customer_ok: customer_ok(settings),
        };
        match confirm.observe(round) {
            Verdict::Confirmed => {
                let changed = model::on_confirmed(&mut state, table, running);
                if changed && !store_state(dir, &state) {
                    log("bank guard: proof seen, but the state file could not be written");
                }
                if armed {
                    log(&format!(
                        "bank guard: confirmed: bank {running} answered through the core and the keeper stayed up; the update is kept"
                    ));
                } else if changed {
                    log(&format!("bank guard: bank {running} recorded as the confirmed bank"));
                }
                return 0;
            }
            Verdict::Expired if !armed => {
                log_ram("bank guard: no proof in this boot's window; nothing recorded");
                return 0;
            }
            Verdict::Expired => {
                let why = format!(
                    "no proof within {} s of boot (management address {}, answer {}, keeper {}, customer {})",
                    settings.confirm_secs,
                    yes(round.mgmt_up),
                    match round.heard {
                        Some(true) => "yes",
                        Some(false) => "no",
                        None => "no targets",
                    },
                    if round.keeper_pid.is_some() { "running" } else { "not running" },
                    yes(round.customer_ok)
                );
                return switch_back(dir, state, table, &why, clock);
            }
            Verdict::Hold => clock.sleep(model::PROBE_EVERY),
        }
    }
}

fn refuse(dir: &Path, state: &mut State, reason: &str) -> i32 {
    model::on_refused(state, reason);
    let stored = store_state(dir, state);
    log(&format!("bank guard: not switching: {reason} (recorded: {})", yes(stored)));
    0
}

/// Raise the old bank in one NV write, read it back, reboot once.
fn switch_back(dir: &Path, mut state: State, boot_table: &Table, why: &str, clock: &mut Clock) -> i32 {
    let Some(session) = state.session.clone().filter(|s| s.open()) else {
        return 0;
    };
    let fallback = session.fallback as usize;
    log(&format!("bank guard: switching back to bank {fallback}: {why}"));
    let now = match agreed_table() {
        Ok(table) => table,
        Err(e) => {
            log(&format!(
                "bank guard: not switching this boot: cannot read the bank table both ways: {e}"
            ));
            return 0;
        }
    };
    if now != *boot_table {
        return refuse(dir, &mut state, "the bank table changed during this boot");
    }
    if now.image(fallback) != session.fallback_image {
        return refuse(dir, &mut state, "the old bank was rewritten since the update");
    }
    if let Err(e) = check_bank(&now, fallback) {
        return refuse(dir, &mut state, &format!("the old bank failed its own check: {e}"));
    }
    let next = match now.select(fallback, 0) {
        Ok(table) => table,
        Err(e) => return refuse(dir, &mut state, &format!("cannot build the new bank table: {e}")),
    };
    model::on_switching(&mut state);
    if !store_state(dir, &state) {
        log("bank guard: cannot record the switch attempt; not switching");
        return 0;
    }
    let written = write_and_verify(&now, &next, fallback);
    if let Some(session) = state.session.as_mut() {
        session.detail = written.detail.clone();
    }
    let _ = store_state(dir, &state);
    log(&format!("bank guard: {}", written.detail));
    if !written.reboot {
        return 0;
    }
    reboot(clock)
}

struct Written {
    detail: String,
    reboot: bool,
}

fn helper_write(table: &Table) -> Result<i32, String> {
    run_helper("write", Some(&table.bytes[..])).map(|(code, _)| code)
}

/// After the write the flash holds the old table or the new one. Reboot unless
/// the write never ran, or the flash shows a table the boot code may refuse.
fn after_write(old: &Table, next: &Table, bank: usize, note: &str) -> Written {
    let vendor = vendor_table().map(|t| t == *next).unwrap_or(false);
    match raw_table() {
        Ok(raw) if raw == *next => Written {
            detail: format!(
                "switched{note}: the raw cmnnv flash selects bank {bank} (vendor copy agrees: {}); rebooting once",
                yes(vendor)
            ),
            reboot: true,
        },
        Ok(raw) if raw == *old => Written {
            detail: format!(
                "the NV write did not reach flash{note}; the flash still selects bank {}; rebooting to retry from a fresh NV state",
                1 - bank
            ),
            reboot: true,
        },
        Ok(raw) if raw.selected().is_ok() => Written {
            detail: format!(
                "the flash holds a bank table the guard did not write{note} (selects bank {}); rebooting",
                raw.selected().unwrap_or(9)
            ),
            reboot: true,
        },
        Ok(_) => Written {
            detail: format!("the flash holds a bank table the boot code may refuse{note}; not rebooting"),
            reboot: false,
        },
        Err(e) => Written {
            detail: format!(
                "the switch was written{note} but the flash could not be read back ({e}); one NV write leaves the old table or the new one, so rebooting"
            ),
            reboot: true,
        },
    }
}

fn write_and_verify(old: &Table, next: &Table, bank: usize) -> Written {
    match helper_write(next) {
        Ok(0) => {}
        Ok(75) => {
            return Written {
                detail: "the firmware updater holds the flash lock; not switching now".into(),
                reboot: false,
            };
        }
        Ok(74) => return after_write(old, next, bank, " (the vendor reported a failed write)"),
        Ok(code) => {
            return Written {
                detail: format!("witcher-nv23 refused the write (exit {code}); nothing was written"),
                reboot: false,
            };
        }
        Err(e) => {
            return Written {
                detail: format!("the bank table was not written: {e}"),
                reboot: false,
            };
        }
    }
    // The NV layer updates its RAM copy before it programs flash, and it skips
    // a write that matches that copy. If the flash missed the first write,
    // write once more with different bytes that select the same bank: one
    // more than the first write gave each part.
    if raw_table().is_ok_and(|raw| raw == *old) {
        if let Ok(retry) = old.select(bank, 1) {
            if helper_write(&retry) == Ok(0) {
                return after_write(old, &retry, bank, " on the second write");
            }
        }
    }
    after_write(old, next, bank, "")
}

fn reboot(clock: &mut Clock) -> i32 {
    // SAFETY: sync takes no arguments.
    unsafe { libc::sync() };
    let program = std::env::var("TITAN_REBOOT").unwrap_or_else(|_| "reboot".into());
    // BusyBox reboot signals init and returns. Wait for it before counting,
    // so the wait starts when the request is in.
    let request = |args: &[&str]| {
        if let Ok(mut child) = Command::new(&program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            let started = Instant::now();
            while matches!(child.try_wait(), Ok(None)) && started.elapsed() < Duration::from_secs(10) {
                thread::sleep(Duration::from_millis(100));
            }
        }
    };
    request(&[]);
    clock.sleep(REBOOT_FORCE_AFTER);
    log("bank guard: the reboot did not happen; forcing it");
    request(&["-f"]);
    clock.sleep(REBOOT_GIVE_UP_AFTER);
    log("bank guard: the forced reboot did not happen either; the switch waits for the next boot");
    0
}

fn arm() -> i32 {
    let Some(dir) = guard_dir() else {
        eprintln!("bank-guard arm: the persistent volume is not mounted");
        return 1;
    };
    let running = match running() {
        Ok(bank) => bank,
        Err(e) => {
            eprintln!("bank-guard arm: {e}");
            return 1;
        }
    };
    let table = match agreed_table() {
        Ok(table) => table,
        Err(e) => {
            eprintln!("bank-guard arm: {e}");
            return 1;
        }
    };
    let selected = match table.selected() {
        Ok(bank) => bank,
        Err(e) => {
            eprintln!("bank-guard arm: {e}");
            return 1;
        }
    };
    if selected == running {
        eprintln!("bank-guard arm: the table still selects the running bank {running}; write the update first");
        return 1;
    }
    let record = ArmRecord {
        target: selected as u8,
        install: table.install(selected),
        boot_id: boot_id(),
    };
    let _ = fs::create_dir_all(&dir);
    let text = serde_json::to_string(&record).unwrap_or_default();
    if record.boot_id.is_empty() || !write_atomic(&dir.join("arm.json"), text.as_bytes()) {
        eprintln!("bank-guard arm: could not record the marker");
        return 1;
    }
    println!("armed: the next boot of bank {selected} must prove itself or the guard switches back to bank {running}");
    0
}

fn preflight() -> i32 {
    let state = match guard_dir().map(|dir| load_state(&dir)) {
        None | Some(Loaded::Fresh) => State::default(),
        Some(Loaded::Ready(state)) => state,
        Some(Loaded::Damaged(e)) => {
            println!("refuse: the bank guard state file is unreadable ({e})");
            return 3;
        }
    };
    let (running, table) = match (running(), agreed_table()) {
        (Ok(running), Ok(table)) => (running, table),
        (Err(e), _) | (_, Err(e)) => {
            println!("unknown: {e}");
            return 1;
        }
    };
    match model::preflight(&state, &table, running) {
        Ok(notes) => {
            println!("ok: an update may write bank {}", 1 - running);
            for note in notes {
                println!("note: {note}");
            }
            0
        }
        Err(e) => {
            println!("refuse: {e}");
            3
        }
    }
}

fn status() -> i32 {
    let dir = guard_dir();
    let state = match dir.as_deref().map(load_state) {
        Some(Loaded::Ready(state)) => Some(state),
        _ => None,
    };
    let running = running();
    let vendor = vendor_table();
    let raw = raw_view();
    let table = match (&vendor, &raw) {
        (Ok(v), Ok(r)) if *v == r.table => Some(v.clone()),
        _ => None,
    };
    let shown = table.clone().or_else(|| vendor.as_ref().ok().cloned());
    let records = shown.as_ref().map(|t| {
        (0..3)
            .flat_map(|part| (0..2).map(move |bank| (part, bank)))
            .map(|(part, bank)| {
                let r = t.record(part, bank);
                json!({
                    "partition": model::PARTITIONS[part][bank],
                    "seq": r.seq,
                    "size": r.size,
                    "adler": format!("{:08x}", r.adler),
                    "problem": t.record_problem(part, bank),
                })
            })
            .collect::<Vec<_>>()
    });
    let preflight = match (&running, &table) {
        (Ok(bank), Some(t)) => match model::preflight(&state.clone().unwrap_or_default(), t, *bank) {
            Ok(notes) => json!({"verdict": "ok", "notes": notes}),
            Err(e) => json!({"verdict": "refuse", "reason": e}),
        },
        _ => json!({"verdict": "unknown"}),
    };
    let settings = dir
        .as_deref()
        .map(|d| model::parse_settings(&read_text(&d.join("config"))))
        .unwrap_or_default();
    let report = json!({
        "running_bank": running.as_ref().ok(),
        "running_error": running.as_ref().err(),
        "views_agree": table.is_some(),
        "vendor_error": vendor.as_ref().err(),
        "raw": match &raw {
            Ok(view) => json!({
                "copy_blocks": view.blocks,
                "selected_copy": view.copy,
                "copy_seqs": view.seqs.iter().map(|s| match s { Ok(seq) => json!(seq), Err(e) => json!(e) }).collect::<Vec<_>>(),
            }),
            Err(e) => json!({"error": e}),
        },
        "selected_bank": shown.as_ref().and_then(|t| t.selected().ok()),
        "records": records,
        "stock_4172": shown.as_ref().map(|t| [0, 1].map(|bank| t.image(bank) == model::STOCK_4172)),
        "settings": {
            "enabled": settings.enabled,
            "confirm_secs": settings.confirm_secs,
            "targets": settings.targets.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "require_customer": settings.require_customer,
        },
        "state": state,
        "preflight": preflight,
    });
    println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
    0
}
